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
        --grafana-password-file PATH
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
    grafana_password_file: Option<PathBuf>,
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
            Long("grafana-password-file") => a.grafana_password_file = Some(p.value()?.into()),
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

/// The cookie jar for Grafana's session, CREATED HERE AND NOT BY CURL.
///
/// curl creates it under whatever umask is in effect — 0644 in a default
/// login shell — under a name that can be guessed from the process id, in a
/// directory everyone may write to. `create_new` on top of the mode: a file
/// that is already there gets a loud error rather than a write through
/// whatever it turns out to be.
fn create_cookie_jar(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating the cookie jar {}", path.display()))?;
    Ok(())
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

    let password = match &a.grafana_password_file {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .with_context(|| format!("{}", p.display()))?
                .trim()
                .to_string(),
        ),
        None => None,
    };

    let settings = Settings {
        prometheus: a
            .prometheus
            .unwrap_or_else(|| "http://localhost:9090".into()),
        loki: a.loki.unwrap_or_else(|| "http://localhost:3100".into()),
        loki_rules: a.loki_rules,
        grafana: a.grafana.unwrap_or_else(|| "http://127.0.0.1:3000".into()),
        grafana_password: password,
        sources,
        long_secs: duration(a.long.as_deref().unwrap_or("7d"))?,
        short_secs: duration(a.short.as_deref().unwrap_or("15m"))?,
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64,
    };

    // Prometheus and Loki live on an internal address and are reached over
    // ssh; Grafana over the local tunnel, with a cookie jar for the session.
    let net = Curl {
        via_ssh: a.via_ssh.clone(),
        cookie_jar: None,
    };
    // The nanoseconds are not decoration: with the pid alone a crashed run
    // leaves a jar behind that `create_new` would then refuse for the next
    // run that happens to get the same pid.
    let jar = std::env::temp_dir().join(format!(
        "crosshair-{}-{}.cookies",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .subsec_nanos()
    ));
    create_cookie_jar(&jar)?;
    let grafana_net = Curl {
        via_ssh: None,
        cookie_jar: Some(jar.clone()),
    };

    let outcome = run(&settings, &cfg, &net, &grafana_net);
    let _ = std::fs::remove_file(&jar);
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

    /// THE JAR CARRIES A GRAFANA SESSION COOKIE and lands in a directory
    /// everyone can write to. Left to curl it would be created under whatever
    /// umask happens to be in effect -- 0644 on a default login shell.
    #[test]
    fn the_cookie_jar_is_created_unreadable_to_others() {
        use std::os::unix::fs::PermissionsExt;
        let p =
            std::env::temp_dir().join(format!("crosshair-jar-mode-{}.cookies", std::process::id()));
        let _ = std::fs::remove_file(&p);
        create_cookie_jar(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&p);
        assert_eq!(
            mode, 0o600,
            "the cookie jar is readable by others: {mode:o}"
        );
    }

    /// And it refuses a file that is already there rather than writing through
    /// whatever it is -- a symlink planted under a predictable name is the
    /// classic temp-file trap.
    #[test]
    fn an_existing_jar_is_refused_not_overwritten() {
        let p = std::env::temp_dir().join(format!(
            "crosshair-jar-exists-{}.cookies",
            std::process::id()
        ));
        std::fs::write(&p, "").unwrap();
        let r = create_cookie_jar(&p);
        let _ = std::fs::remove_file(&p);
        assert!(r.is_err(), "an existing jar must not be reused");
    }
}
