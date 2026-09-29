//! The CLI. One subcommand: `crosshair check`.

use anyhow::{Context, Result};
use crosshair::config::Config;
use crosshair::http::Curl;
use crosshair::report;
use crosshair::run::{SOURCES, Settings, run};
use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "\
crosshair — does this rule point at anything real?

USAGE:
    crosshair check [OPTIONS]

Puts every selector of every alerting rule and dashboard panel to the running
instance, over TWO lookback windows, and tells dead apart from merely quiet.
Every source proves first that it can find something and that it does not find
everything — without that, \"0 dead rules\" cannot be told from a query that
went nowhere.

OPTIONS:
        --prometheus URL     default http://localhost:9090
        --loki URL           default http://localhost:3100
        --loki-rules FILE    the LogQL rules; the Ruler API is not enabled here
        --grafana URL        default http://127.0.0.1:3000
        --grafana-token-file PATH
                             a Grafana service-account token, role Viewer, sent
                             as `Authorization: Bearer`; the file holds the
                             token alone (a trailing newline is fine)
        --via-ssh TARGET     reach prometheus and loki through ssh + curl
        --source LIST        prometheus,loki,grafana (default: all three);
                             an unknown name is an error, never a silent no-op
        --long DURATION      long window, default 7d
        --short DURATION     short window, default 15m
    -c, --config FILE        exceptions, each needs a reason
    -h, --help
    -V, --version

EXIT STATUS:
    0  nothing dead, both controls right
    1  at least one dead selector, or an expression the instance refuses
    2  tool failure — a control failed, an API did not answer, an inventory
       was empty, an expression did not parse, an exception matched nothing,
       or the run checked no selector at all
";

#[derive(Default)]
struct Args {
    command: String,
    prometheus: Option<String>,
    loki: Option<String>,
    loki_rules: Option<PathBuf>,
    grafana: Option<String>,
    grafana_token_file: Option<PathBuf>,
    via_ssh: Option<String>,
    sources: Option<String>,
    long: Option<String>,
    short: Option<String>,
    config: Option<PathBuf>,
}

fn parse_args() -> Result<Option<Args>, lexopt::Error> {
    use lexopt::prelude::*;
    let mut a = Args::default();
    let mut p = lexopt::Parser::from_env();
    while let Some(arg) = p.next()? {
        match arg {
            Long("prometheus") => a.prometheus = Some(p.value()?.string()?),
            Long("loki") => a.loki = Some(p.value()?.string()?),
            Long("loki-rules") => a.loki_rules = Some(p.value()?.into()),
            Long("grafana") => a.grafana = Some(p.value()?.string()?),
            Long("grafana-token-file") => a.grafana_token_file = Some(p.value()?.into()),
            Long("via-ssh") => a.via_ssh = Some(p.value()?.string()?),
            Long("source") => a.sources = Some(p.value()?.string()?),
            Long("long") => a.long = Some(p.value()?.string()?),
            Long("short") => a.short = Some(p.value()?.string()?),
            Short('c') | Long("config") => a.config = Some(p.value()?.into()),
            Short('h') | Long("help") => {
                print!("{HELP}");
                return Ok(None);
            }
            Short('V') | Long("version") => {
                println!("crosshair {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            Value(v) if a.command.is_empty() => a.command = v.string()?,
            _ => return Err(arg.unexpected()),
        }
    }
    Ok(Some(a))
}

/// `prometheus,loki` — the sources to run, and AN UNKNOWN NAME IS AN ERROR.
///
/// Until 0.1.1 the list went through unchecked and `run()` matched it with
/// `any(|x| x == "prometheus")`: `--source promethues` ran nothing, produced
/// an empty outcome, exited 0 and printed "Every selector points at series
/// that exist." A tool built to tell "nothing is wrong" apart from "nothing
/// was asked" must not fall for it itself.
fn parse_sources(list: &str) -> Result<Vec<String>, String> {
    let names: Vec<String> = list
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let valid = SOURCES.join(", ");
    if names.is_empty() {
        return Err(format!(
            "--source names no source at all (valid: {valid}) — an empty list checks nothing"
        ));
    }
    for n in &names {
        if !SOURCES.contains(&n.as_str()) {
            return Err(format!("--source: unknown source {n:?} (valid: {valid})"));
        }
    }
    Ok(names)
}

/// The token out of `--grafana-token-file`: the file holds the token and
/// nothing else. ONE trailing newline is tolerated, because `echo` and every
/// editor write one; anything else that is not a visible ASCII character is
/// refused rather than trimmed.
///
/// WHY SO STRICT: the token goes into a header FILE, one header per line. A
/// token with a second line in it would be a second header, and a space in
/// the middle is a file that holds something other than a token.
///
/// AND NO ERROR NAMES THE VALUE. The message says what is wrong with the file,
/// never what is in it — it lands on stderr and in whatever log runs this.
fn read_token(text: &str) -> Result<String> {
    let t = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if t.is_empty() {
        anyhow::bail!("the grafana token file is empty");
    }
    if !t.bytes().all(|b| b.is_ascii_graphic()) {
        anyhow::bail!(
            "the grafana token file holds more than one token: whitespace, a second line or a non-ASCII character"
        );
    }
    Ok(t.to_string())
}

/// A file for a secret, CREATED HERE AND NOT BY CURL: mode 0600 from the
/// first byte, and `create_new`, so a file already sitting under that name —
/// a symlink planted in a directory everyone may write to — is a loud error
/// rather than a write through whatever it turns out to be.
fn create_private(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Removes the header file on every way out of `real_main`, the `?` ones
/// included — it carries the token.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `7d`, `90m`, `3600` — seconds out.
fn duration(s: &str) -> Result<i64> {
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let secs = num
        .parse::<i64>()
        .with_context(|| format!("duration {s}"))?
        * mult;
    if secs <= 0 {
        anyhow::bail!(
            "duration {s} is not positive — a window of zero length makes every selector look dead"
        );
    }
    Ok(secs)
}

fn real_main() -> Result<u8> {
    let Some(a) = parse_args()? else { return Ok(0) };
    if a.command != "check" {
        print!("{HELP}");
        return Ok(2);
    }
    // BEFORE ANY FILE IS READ AND ANY SECRET DECRYPTED. Checked here and not
    // inside `parse_args` for one reason, and it is visible in the output:
    // `lexopt::Error::Custom` is its own `source()`, so anyhow's `{:#}`
    // printed the whole sentence twice.
    let sources = match &a.sources {
        Some(list) => parse_sources(list).map_err(anyhow::Error::msg)?,
        None => SOURCES.iter().map(|s| s.to_string()).collect(),
    };
    let cfg: Config = match &a.config {
        Some(p) => toml::from_str(
            &std::fs::read_to_string(p).with_context(|| format!("{}", p.display()))?,
        )?,
        None => Config::default(),
    };
    cfg.validate()?;

    let token = match &a.grafana_token_file {
        Some(p) => Some(read_token(
            &std::fs::read_to_string(p).with_context(|| format!("{}", p.display()))?,
        )?),
        None => None,
    };

    let settings = Settings {
        prometheus: a
            .prometheus
            .unwrap_or_else(|| "http://localhost:9090".into()),
        loki: a.loki.unwrap_or_else(|| "http://localhost:3100".into()),
        loki_rules: a.loki_rules,
        grafana: a.grafana.unwrap_or_else(|| "http://127.0.0.1:3000".into()),
        sources,
        long_secs: duration(a.long.as_deref().unwrap_or("7d"))?,
        short_secs: duration(a.short.as_deref().unwrap_or("15m"))?,
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64,
    };

    // Prometheus and Loki live on an internal address and are reached over
    // ssh; Grafana over the local tunnel, with the token in a header file.
    // Prometheus and Loki never see the token: it belongs to Grafana alone.
    let net = Curl {
        via_ssh: a.via_ssh.clone(),
        header_file: None,
    };
    let headers = match token {
        Some(t) => {
            // The nanoseconds are not decoration: with the pid alone a
            // crashed run leaves a file behind that `create_new` would then
            // refuse for the next run that happens to get the same pid.
            let path = std::env::temp_dir().join(format!(
                "crosshair-{}-{}.headers",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .subsec_nanos()
            ));
            // Empty first, the guard second, the token third: a failed
            // `create_new` means the file is SOMEONE ELSE'S, and a guard
            // made before it would delete that.
            create_private(&path, "")?;
            let guard = RemoveOnDrop(path);
            std::fs::write(&guard.0, format!("Authorization: Bearer {t}\n"))
                .with_context(|| format!("writing {}", guard.0.display()))?;
            Some(guard)
        }
        None => None,
    };
    let grafana_net = Curl {
        via_ssh: None,
        header_file: headers.as_ref().map(|g| g.0.clone()),
    };

    let outcome = run(&settings, &cfg, &net, &grafana_net);
    drop(headers);
    report::print(&outcome);
    Ok(outcome.exit_code())
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("ERROR: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_seconds_are_seconds() {
        assert_eq!(duration("3600").unwrap(), 3600);
    }

    #[test]
    fn seconds_suffix_is_one_to_one() {
        assert_eq!(duration("45s").unwrap(), 45);
    }

    #[test]
    fn minutes_are_multiplied_by_sixty() {
        assert_eq!(duration("15m").unwrap(), 900);
    }

    #[test]
    fn hours_are_multiplied_by_thirty_six_hundred() {
        assert_eq!(duration("1h").unwrap(), 3600);
    }

    #[test]
    fn days_are_multiplied_by_eightysix_thousand_four_hundred() {
        assert_eq!(duration("7d").unwrap(), 604800);
    }

    /// A NONSENSE VALUE MUST NOT SILENTLY BECOME ZERO. A zero-length window
    /// makes every selector look dead — a silent catastrophe, not a loud one.
    #[test]
    fn nonsense_is_an_error_not_zero() {
        assert!(duration("banana").is_err());
        assert!(duration("").is_err());
        assert!(duration("d").is_err());
        assert!(duration("soon").is_err());
    }

    /// `--long 7d` and `--short 15m` still resolve as before — the guard
    /// below must not touch the ordinary, positive cases.
    #[test]
    fn seven_days_is_still_604800() {
        assert_eq!(duration("7d").unwrap(), 604800);
    }

    #[test]
    fn fifteen_minutes_is_still_900() {
        assert_eq!(duration("15m").unwrap(), 900);
    }

    #[test]
    fn bare_3600_is_still_3600() {
        assert_eq!(duration("3600").unwrap(), 3600);
    }

    /// A ZERO-LENGTH WINDOW MUST BE REJECTED, NOT ACCEPTED AS ZERO SECONDS.
    /// `--short 0` would make every selector look dead — a report of a
    /// hundred dead rules that is entirely an artefact of the flag.
    #[test]
    fn zero_is_rejected_not_accepted() {
        assert!(duration("0").is_err());
    }

    /// AN INVERTED WINDOW IS THE SAME CATASTROPHE FROM THE OTHER SIDE.
    #[test]
    fn a_negative_duration_is_rejected() {
        assert!(duration("-5m").is_err());
    }

    /// THE WHOLE POINT OF THE FLAG IS THAT IT SELECTS; A NAME NOBODY KNOWS
    /// SELECTS NOTHING. `--source promethues` used to run not a single check,
    /// produce an empty outcome, exit 0 and print "Every selector points at
    /// series that exist." -- this tool's own failure mode, one level up.
    #[test]
    fn an_unknown_source_is_an_error() {
        let e = parse_sources("promethues").unwrap_err();
        assert!(e.contains("promethues"), "the message must name it: {e}");
        assert!(e.contains("prometheus"), "and list the valid ones: {e}");
    }

    /// One good name does not launder a bad one next to it.
    #[test]
    fn an_unknown_source_beside_a_known_one_is_still_an_error() {
        assert!(parse_sources("prometheus,grafna").is_err());
    }

    /// An empty list is not "all of them", it is a typo: `--source ""` or
    /// `--source ,` would otherwise check nothing and report success.
    #[test]
    fn an_empty_source_list_is_an_error() {
        assert!(parse_sources("").is_err());
        assert!(parse_sources(",").is_err());
        assert!(parse_sources("   ").is_err());
    }

    #[test]
    fn the_three_known_sources_are_accepted() {
        assert_eq!(parse_sources("prometheus").unwrap(), vec!["prometheus"]);
        assert_eq!(
            parse_sources(" loki , grafana ").unwrap(),
            vec!["loki", "grafana"]
        );
        assert_eq!(parse_sources("prometheus,loki,grafana").unwrap().len(), 3);
    }

    /// THE HEADER FILE CARRIES THE TOKEN and lands in a directory everyone
    /// can write to: 0600 from the first byte.
    #[test]
    fn a_private_file_is_created_unreadable_to_others() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!(
            "crosshair-private-mode-{}.headers",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        create_private(&p, "x").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&p);
        assert_eq!(
            mode, 0o600,
            "the header file is readable by others: {mode:o}"
        );
    }

    /// And it refuses a file that is already there rather than writing through
    /// whatever it is -- a symlink planted under a predictable name is the
    /// classic temp-file trap.
    #[test]
    fn an_existing_file_is_refused_not_overwritten() {
        let p = std::env::temp_dir().join(format!(
            "crosshair-private-exists-{}.headers",
            std::process::id()
        ));
        std::fs::write(&p, "").unwrap();
        let r = create_private(&p, "x");
        let _ = std::fs::remove_file(&p);
        assert!(r.is_err(), "an existing file must not be reused");
    }

    /// `echo glsa_… > file` writes a newline; so does every editor.
    #[test]
    fn one_trailing_newline_is_tolerated() {
        assert_eq!(read_token("glsa_abc\n").unwrap(), "glsa_abc");
        assert_eq!(read_token("glsa_abc\r\n").unwrap(), "glsa_abc");
        assert_eq!(read_token("glsa_abc").unwrap(), "glsa_abc");
    }

    #[test]
    fn an_empty_token_file_is_an_error() {
        assert!(read_token("").is_err());
        assert!(read_token("\n").is_err());
    }

    /// A SECOND LINE WOULD BE A SECOND HEADER in the file curl reads.
    #[test]
    fn a_token_with_a_second_line_or_a_space_is_refused() {
        assert!(read_token("glsa_abc\nX-Evil: 1\n").is_err());
        assert!(read_token("glsa_abc\n\n").is_err());
        assert!(read_token("glsa abc").is_err());
    }

    /// AND THE REFUSAL DOES NOT QUOTE WHAT IT REFUSED.
    #[test]
    fn a_refused_token_is_not_in_the_error() {
        let e = read_token("glsa_geheim wert\n").unwrap_err();
        assert!(!format!("{e:#}").contains("geheim"), "{e:#}");
    }
}
