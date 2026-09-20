//! Exceptions, each with a reason — the unit-lint and leakwatch pattern.
//!
//! An exception that no longer matches anything turns the run red. A list that
//! ages silently is worse than no list.

use crate::selector::{Check, Origin};
use anyhow::{Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default, rename = "exception")]
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Deserialize)]
pub struct Exception {
    /// Scope: an alerting or recording rule by name …
    pub rule: Option<String>,
    /// … or a dashboard, optionally narrowed to one panel.
    pub dashboard: Option<String>,
    pub panel: Option<String>,
    /// Optional: only this one selector inside the scope. Copy it from the
    /// report — crosshair prints the normalised form it asks with.
    pub selector: Option<String>,
    /// Mandatory. An exception without a reason is an omission.
    pub reason: String,
    /// Opt out of the staleness check for a finding that legitimately comes
    /// and goes. Deliberately per entry: a file where everything is `optional`
    /// has given up the check.
    #[serde(default)]
    pub optional: bool,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        for e in &self.exceptions {
            if e.rule.is_none() && e.dashboard.is_none() {
                bail!(
                    "an exception must name a rule or a dashboard (reason: {})",
                    e.reason.lines().next().unwrap_or("")
                );
            }
            if e.rule.is_some() && e.dashboard.is_some() {
                bail!("an exception names both a rule and a dashboard — say which one");
            }
        }
        Ok(())
    }

    pub fn covers(&self, c: &Check) -> bool {
        self.exceptions.iter().any(|e| matches(e, c))
    }

    /// Exceptions that suppressed nothing in this run.
    pub fn unused(&self, dead: &[Check]) -> Vec<String> {
        self.exceptions
            .iter()
            .filter(|e| !e.optional)
            .filter(|e| !dead.iter().any(|c| matches(e, c)))
            .map(label)
            .collect()
    }
}

fn matches(e: &Exception, c: &Check) -> bool {
    let scope = match (&c.origin, &e.rule, &e.dashboard) {
        (Origin::Rule { rule, .. }, Some(want), None) => rule == want,
        (
            Origin::Panel {
                dashboard, panel, ..
            },
            None,
            Some(want),
        ) => dashboard == want && e.panel.as_ref().is_none_or(|p| p == panel),
        _ => false,
    };
    scope && e.selector.as_ref().is_none_or(|s| *s == c.selector)
}

fn label(e: &Exception) -> String {
    let scope = e
        .rule
        .clone()
        .or_else(|| match (&e.dashboard, &e.panel) {
            (Some(d), Some(p)) => Some(format!("{d} \"{p}\"")),
            (Some(d), None) => Some(d.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "(no scope)".into());
    match &e.selector {
        Some(s) => format!("{scope} / {s}"),
        None => scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::{Origin, Verdict};

    fn dead(rule: &str, selector: &str) -> Check {
        Check {
            origin: Origin::Rule {
                source: "prometheus".into(),
                rule: rule.into(),
            },
            selector: selector.into(),
            verdict: Verdict::Dead,
            excepted: false,
        }
    }

    #[test]
    fn an_exception_without_a_reason_is_refused() {
        let r: Result<Config, _> = toml::from_str("[[exception]]\nrule = \"X\"\n");
        assert!(r.is_err(), "an exception without a reason was accepted");
    }

    #[test]
    fn an_exception_naming_neither_rule_nor_dashboard_is_refused() {
        let c: Config = toml::from_str("[[exception]]\nreason = \"weil\"\n").unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_rule_exception_covers_every_dead_selector_of_that_rule() {
        let c: Config = toml::from_str(
            "[[exception]]\nrule = \"SteckdoseStumm\"\nreason = \"das Geraet ist als nicht vorhanden deklariert\"\n",
        )
        .unwrap();
        assert!(c.covers(&dead("SteckdoseStumm", "steckdose_watt")));
        assert!(!c.covers(&dead("AndereRegel", "steckdose_watt")));
    }

    /// With a selector the exception is narrower — the other dead selectors of
    /// the same rule stay red.
    #[test]
    fn a_selector_narrows_the_exception() {
        let c: Config = toml::from_str(
            "[[exception]]\nrule = \"Zwei\"\nselector = \"steckdose_watt\"\nreason = \"noch nicht in Betrieb\"\n",
        )
        .unwrap();
        assert!(c.covers(&dead("Zwei", "steckdose_watt")));
        assert!(!c.covers(&dead("Zwei", "etwas_anderes")));
    }

    /// AN EXCEPTION THAT MATCHES NOTHING TURNS THE RUN RED — the unit-lint
    /// rule. A list that ages silently is worse than no list.
    #[test]
    fn an_exception_that_matches_nothing_is_reported() {
        let c: Config =
            toml::from_str("[[exception]]\nrule = \"Weg\"\nreason = \"trifft nichts mehr\"\n")
                .unwrap();
        assert_eq!(c.unused(&[]), vec!["Weg".to_string()]);
    }

    /// `optional` exists FROM THE FIRST VERSION, and the reason was paid for on
    /// 2026-09-20: leakwatch stood red three hours after rollout because
    /// exceptions matched nothing — one of them had 18 hits at noon. Frequency
    /// is no protection when it is a burst and not a rate.
    #[test]
    fn an_optional_exception_is_never_reported_as_unused() {
        let c: Config = toml::from_str(
            "[[exception]]\nrule = \"Schubweise\"\noptional = true\nreason = \"kommt und geht\"\n",
        )
        .unwrap();
        assert!(c.unused(&[]).is_empty());
    }

    #[test]
    fn a_panel_exception_matches_dashboard_and_panel() {
        let c: Config = toml::from_str(
            "[[exception]]\ndashboard = \"Services/arr-library.json\"\npanel = \"Library size\"\nreason = \"Fremd-Dashboard\"\n",
        )
        .unwrap();
        let check = Check {
            origin: Origin::Panel {
                dashboard: "Services/arr-library.json".into(),
                panel: "Library size".into(),
                refid: "A".into(),
            },
            selector: "radarr_movie_filesize_total".into(),
            verdict: Verdict::Dead,
            excepted: false,
        };
        assert!(c.covers(&check));
    }

    /// AUDIT 1: An exception naming both a rule and a dashboard must be rejected.
    #[test]
    fn an_exception_naming_both_rule_and_dashboard_is_refused() {
        let c: Config = toml::from_str(
            "[[exception]]\nrule = \"X\"\ndashboard = \"Y\"\nreason = \"ambiguous\"\n",
        )
        .unwrap();
        assert!(c.validate().is_err());
    }

    /// AUDIT 2: A panel exception that narrows by panel should NOT cover a different panel of the same dashboard.
    #[test]
    fn a_panel_exception_with_panel_narrowing_does_not_cover_different_panel() {
        let c: Config = toml::from_str(
            "[[exception]]\ndashboard = \"Services/arr-library.json\"\npanel = \"Library size\"\nreason = \"Fremd-Dashboard\"\n",
        )
        .unwrap();
        let different_panel_check = Check {
            origin: Origin::Panel {
                dashboard: "Services/arr-library.json".into(),
                panel: "Different Panel".into(),
                refid: "B".into(),
            },
            selector: "radarr_movie_filesize_total".into(),
            verdict: Verdict::Dead,
            excepted: false,
        };
        assert!(!c.covers(&different_panel_check));
    }
}
