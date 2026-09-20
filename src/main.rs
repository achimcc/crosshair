//! The CLI. One subcommand: `crosshair check`.

use anyhow::{Context, Result};
use crosshair::config::Config;
use crosshair::http::Curl;
use crosshair::report;
use crosshair::run::{Settings, run};
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
        --source LIST        prometheus,loki,grafana (default: all three)
        --long DURATION      long window, default 7d
        --short DURATION     short window, default 15m
    -c, --config FILE        exceptions, each needs a reason
    -h, --help
    -V, --version

EXIT STATUS:
    0  nothing dead, both controls right
    1  at least one dead selector, or an expression the instance refuses
    2  tool failure — a control failed, an API did not answer, an expression
       did not parse, or an exception matched nothing
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

/// `7d`, `90m`, `3600` — seconds out.
fn duration(s: &str) -> Result<i64> {
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    Ok(num
        .parse::<i64>()
        .with_context(|| format!("duration {s}"))?
        * mult)
}

fn real_main() -> Result<u8> {
    let Some(a) = parse_args()? else { return Ok(0) };
    if a.command != "check" {
        print!("{HELP}");
        return Ok(2);
    }
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
        sources: a
            .sources
            .unwrap_or_else(|| "prometheus,loki,grafana".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
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
    let jar = std::env::temp_dir().join(format!("crosshair-{}.cookies", std::process::id()));
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
    }
}
