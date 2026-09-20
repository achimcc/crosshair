//! The pipeline: sources -> expressions -> selectors -> two windows -> verdict.
//!
//! EVERY SOURCE RUNS ITS OWN POSITIVE CONTROL, and it runs it FIRST. A broken
//! Loki path must not be covered by a healthy Prometheus path — the same
//! decision as leakwatch's canary per adapter.

use crate::config::Config;
use crate::grafana::{Grafana, QueryOutcome, Skip, targets};
use crate::http::Http;
use crate::loki::{self, Loki};
use crate::prometheus::Prometheus;
use crate::selector::{Check, Origin, Verdict, judge};
use crate::{logql, promql};
use std::collections::HashMap;
use std::path::PathBuf;

/// The sources this tool knows, and the only names `--source` accepts.
/// `main.rs` validates against this list; `run()` matches against it.
pub const SOURCES: [&str; 3] = ["prometheus", "loki", "grafana"];

pub struct Settings {
    pub prometheus: String,
    pub loki: String,
    pub loki_rules: Option<PathBuf>,
    pub grafana: String,
    pub grafana_password: Option<String>,
    pub sources: Vec<String>,
    pub long_secs: i64,
    pub short_secs: i64,
    pub now: i64,
}

#[derive(Default)]
pub struct Outcome {
    pub checks: Vec<Check>,
    /// Findings that are not a verdict about a selector: a rule whose
    /// expression the instance refuses, a panel Grafana errors on.
    pub findings: Vec<String>,
    /// Things worth naming that change no exit code — skipped targets,
    /// expressions without a selector.
    pub notes: Vec<String>,
    pub tool_failures: Vec<String>,
}

impl Outcome {
    pub fn exit_code(&self) -> u8 {
        if !self.tool_failures.is_empty() {
            return 2;
        }
        let dead = self
            .checks
            .iter()
            .any(|c| c.verdict == Verdict::Dead && !c.excepted);
        if dead || !self.findings.is_empty() {
            1
        } else {
            0
        }
    }
}

pub fn run(s: &Settings, cfg: &Config, net: &dyn Http, grafana_net: &dyn Http) -> Outcome {
    let mut o = Outcome::default();
    let long = s.now - s.long_secs;
    let short = s.now - s.short_secs;

    let mut prometheus_control_passed = false;
    if s.sources.iter().any(|x| x == "prometheus") {
        prometheus_control_passed = prometheus_source(s, &mut o, net, long, short);
    }
    if s.sources.iter().any(|x| x == "loki") {
        loki_source(s, &mut o, net, long, short);
    }
    if s.sources.iter().any(|x| x == "grafana") {
        grafana_source(
            s,
            &mut o,
            grafana_net,
            long,
            short,
            net,
            prometheus_control_passed,
        );
    }

    // Exceptions last: they can only mark what the run actually found.
    for c in &mut o.checks {
        if c.verdict == Verdict::Dead && cfg.covers(c) {
            c.excepted = true;
        }
    }
    // THE STALENESS CHECK NEEDS A FULL RUN. It asks the whole file whether
    // every entry still suppressed something — and a narrowed run never even
    // looked at the rules and panels the other sources own. With
    // `--source loki` the first non-`optional` entry scoped to a Prometheus
    // rule would turn every such run into an exit 2 for no reason at all.
    if s.sources.len() < SOURCES.len() {
        o.notes.push(format!(
            "the staleness check over the exception file was skipped: this run looked at {} of {} sources, and an entry scoped to one of the others would look unused without being it",
            s.sources.len(),
            SOURCES.len()
        ));
    } else {
        let dead: Vec<Check> = o
            .checks
            .iter()
            .filter(|c| c.verdict == Verdict::Dead)
            .cloned()
            .collect();
        for u in cfg.unused(&dead) {
            o.tool_failures
                .push(format!("exception matched nothing any more: {u}"));
        }
    }

    // THE BACKSTOP UNDER EVERY OTHER GUARD: a run that produced not one
    // check and not one failure has said nothing, and an empty `Outcome`
    // otherwise exits 0 with "Every selector points at series that exist."
    // `--source` is validated in `main`, so the known way in is closed — this
    // catches the ones nobody has thought of yet.
    //
    // A finding counts as having looked: an expression the instance refuses
    // IS a statement about a rule, and turning that exit 1 into an exit 2
    // would bury it under a complaint about the run.
    if o.checks.is_empty() && o.findings.is_empty() && o.tool_failures.is_empty() {
        o.tool_failures.push(
            "this run checked not a single selector — it looked at nothing and says nothing about the rules".into(),
        );
    }
    o
}

/// Returns whether the positive control passed — the Grafana source needs
/// the same answer and must not pay for it twice.
fn prometheus_source(s: &Settings, o: &mut Outcome, net: &dyn Http, long: i64, short: i64) -> bool {
    let p = Prometheus {
        http: net,
        base: s.prometheus.clone(),
    };
    if let Err(e) = p.control(long, s.now) {
        o.tool_failures.push(format!("prometheus {e}"));
        return false;
    }
    let rules = match p.rules() {
        Ok(r) => r,
        Err(e) => {
            o.tool_failures.push(format!("prometheus rules: {e}"));
            return true;
        }
    };
    // One question per distinct selector, not per rule: 95 distinct selectors
    // in this repo out of 101 occurrences, many of them shared between rules.
    let mut cache: HashMap<String, (usize, usize)> = HashMap::new();
    for r in rules {
        // `unknown` IS NOT A FINDING. Prometheus reports it for a rule it has
        // loaded but not yet evaluated, and `scripts/wartung.sh` runs
        // crosshair right after a deploy that restarts obs-01 — a rule that
        // is merely young would abort the maintenance window on exit 1.
        if r.health == "unknown" {
            o.notes.push(format!(
                "{}: prometheus has loaded it but not evaluated it yet (health unknown)",
                r.name
            ));
        } else if r.health != "ok" && !r.health.is_empty() {
            o.findings.push(format!(
                "{} is unhealthy in prometheus ({}): {}",
                r.name, r.health, r.last_error
            ));
        }
        let sels = match promql::selectors(&r.expr) {
            Ok(s) => s,
            Err(e) => {
                o.tool_failures
                    .push(format!("{}: cannot parse its expression: {e}", r.name));
                continue;
            }
        };
        if sels.is_empty() {
            o.notes.push(format!(
                "{}: no vector selector at all ({})",
                r.name, r.expr
            ));
            continue;
        }
        for sel in sels {
            let counts = match cache.get(&sel) {
                Some(c) => *c,
                None => match (p.series(&sel, long, s.now), p.series(&sel, short, s.now)) {
                    (Ok(l), Ok(sh)) => {
                        cache.insert(sel.clone(), (l, sh));
                        (l, sh)
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        o.tool_failures.push(format!("prometheus series: {e}"));
                        continue;
                    }
                },
            };
            o.checks.push(Check {
                origin: Origin::Rule {
                    source: "prometheus".into(),
                    rule: r.name.clone(),
                },
                selector: sel,
                verdict: judge(counts.0, counts.1),
                excepted: false,
            });
        }
    }
    true
}

fn loki_source(s: &Settings, o: &mut Outcome, net: &dyn Http, long: i64, short: i64) {
    let Some(path) = &s.loki_rules else {
        o.tool_failures
            .push("loki: --loki-rules is missing and the Ruler API is not available here".into());
        return;
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            o.tool_failures
                .push(format!("loki rules {}: {e}", path.display()));
            return;
        }
    };
    let rules = match loki::rules_from_yaml(&text) {
        Ok(r) => r,
        Err(e) => {
            o.tool_failures.push(format!("loki rules: {e}"));
            return;
        }
    };
    let l = Loki {
        http: net,
        base: s.loki.clone(),
    };
    let ns = 1_000_000_000i64;
    if let Err(e) = l.control(long * ns, s.now * ns) {
        o.tool_failures.push(format!("loki {e}"));
        return;
    }
    let mut cache: HashMap<String, (usize, usize)> = HashMap::new();
    for r in rules {
        match l.evaluates(&r.expr, short * ns, s.now * ns) {
            Ok(None) => {}
            Ok(Some(why)) => o.findings.push(format!(
                "{}: loki does not evaluate the expression: {why}",
                r.name
            )),
            Err(e) => o.tool_failures.push(format!("{}: {e}", r.name)),
        }
        let sels = logql::stream_selectors(&r.expr);
        if sels.is_empty() {
            o.notes
                .push(format!("{}: no stream selector at all", r.name));
            continue;
        }
        for sel in sels {
            let counts = match cache.get(&sel) {
                Some(c) => *c,
                None => match (
                    l.series(&sel, long * ns, s.now * ns),
                    l.series(&sel, short * ns, s.now * ns),
                ) {
                    (Ok(a), Ok(b)) => {
                        cache.insert(sel.clone(), (a, b));
                        (a, b)
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        o.tool_failures.push(format!("loki series: {e}"));
                        continue;
                    }
                },
            };
            o.checks.push(Check {
                origin: Origin::Rule {
                    source: "loki".into(),
                    rule: r.name.clone(),
                },
                selector: sel,
                verdict: judge(counts.0, counts.1),
                excepted: false,
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn grafana_source(
    s: &Settings,
    o: &mut Outcome,
    net: &dyn Http,
    long: i64,
    short: i64,
    prom_net: &dyn Http,
    prometheus_control_passed: bool,
) {
    let g = Grafana {
        http: net,
        base: s.grafana.clone(),
    };
    if let Some(pw) = &s.grafana_password
        && let Err(e) = g.login(pw)
    {
        o.tool_failures.push(format!("grafana: {e}"));
        return;
    }
    if let Err(e) = g.control() {
        o.tool_failures.push(format!("grafana: {e}"));
        return;
    }
    let p = Prometheus {
        http: prom_net,
        base: s.prometheus.clone(),
    };
    // THIS SOURCE HAS TWO LEGS AND §6 WANTS A CONTROL BEFORE EACH. Grafana's
    // own control covers the `/api/ds/query` leg; every panel VERDICT below
    // comes from `p.series()` straight against Prometheus, and a Prometheus
    // that answers `data: []` to everything would make every panel look dead
    // while Grafana's control passed happily.
    //
    // Skipped when the Prometheus source already ran it and it passed in this
    // same run: the same two questions to the same instance, answered
    // minutes apart, prove nothing the first pair did not.
    if !prometheus_control_passed && let Err(e) = p.control(long, s.now) {
        o.tool_failures
            .push(format!("prometheus (the panels are judged against it) {e}"));
        return;
    }
    let dashboards = match g.dashboards() {
        Ok(d) => d,
        Err(e) => {
            o.tool_failures.push(format!("grafana search: {e}"));
            return;
        }
    };
    let mut cache: HashMap<String, (usize, usize)> = HashMap::new();
    for (uid, name) in dashboards {
        let doc = match g.dashboard(&uid) {
            Ok(d) => d,
            Err(e) => {
                o.tool_failures.push(format!("grafana {name}: {e}"));
                continue;
            }
        };
        let (targets, skipped) = targets(&doc);
        for (refid, why) in skipped {
            let text = match why {
                Skip::OtherDatasource(d) => format!("datasource {d}"),
                Skip::UnresolvedVariable => "dashboard variable".to_string(),
            };
            o.notes.push(format!("{name} [{refid}] skipped: {text}"));
        }
        if targets.is_empty() {
            continue;
        }
        // THROUGH GRAFANA, because a wrong datasource uid only shows there.
        let exprs: Vec<String> = targets.iter().map(|t| t.expr.clone()).collect();
        match g.query(&exprs) {
            Ok(outcomes) => {
                for (t, out) in targets.iter().zip(outcomes) {
                    if let QueryOutcome::Error(e) = out {
                        o.findings.push(format!(
                            "{name} \"{}\" [{}]: grafana error: {e}",
                            t.panel, t.refid
                        ));
                    }
                }
            }
            Err(e) => o.tool_failures.push(format!("grafana query {name}: {e}")),
        }
        // AND THE SELECTOR PATH ON TOP, because it says WHICH part of an
        // expression points at nothing — the 2026-09-06 case had two summands
        // and one of them was enough to empty the panel.
        for t in targets {
            let sels = match promql::selectors(&t.expr) {
                Ok(s) => s,
                Err(e) => {
                    o.tool_failures
                        .push(format!("{name} [{}]: cannot parse: {e}", t.refid));
                    continue;
                }
            };
            for sel in sels {
                let counts = match cache.get(&sel) {
                    Some(c) => *c,
                    None => match (p.series(&sel, long, s.now), p.series(&sel, short, s.now)) {
                        (Ok(a), Ok(b)) => {
                            cache.insert(sel.clone(), (a, b));
                            (a, b)
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            o.tool_failures.push(format!("prometheus series: {e}"));
                            continue;
                        }
                    },
                };
                o.checks.push(Check {
                    origin: Origin::Panel {
                        dashboard: name.clone(),
                        panel: t.panel.clone(),
                        refid: t.refid.clone(),
                    },
                    selector: sel,
                    verdict: judge(counts.0, counts.1),
                    excepted: false,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::{Origin, Verdict};

    fn check(v: Verdict, excepted: bool) -> Check {
        Check {
            origin: Origin::Rule {
                source: "prometheus".into(),
                rule: "R".into(),
            },
            selector: "x".into(),
            verdict: v,
            excepted,
        }
    }

    #[test]
    fn nothing_dead_and_no_failure_is_zero() {
        let o = Outcome {
            checks: vec![check(Verdict::Live, false)],
            ..Default::default()
        };
        assert_eq!(o.exit_code(), 0);
    }

    /// `quiet` NEVER changes the exit code. It is a hint, like `leer` in
    /// dashboard-pruefen — an empty health table is the normal state of a
    /// healthy system.
    #[test]
    fn quiet_alone_is_still_zero() {
        let o = Outcome {
            checks: vec![check(Verdict::Quiet, false)],
            ..Default::default()
        };
        assert_eq!(o.exit_code(), 0);
    }

    #[test]
    fn a_dead_selector_is_one() {
        let o = Outcome {
            checks: vec![check(Verdict::Dead, false)],
            ..Default::default()
        };
        assert_eq!(o.exit_code(), 1);
    }

    #[test]
    fn an_excepted_dead_selector_is_zero() {
        let o = Outcome {
            checks: vec![check(Verdict::Dead, true)],
            ..Default::default()
        };
        assert_eq!(o.exit_code(), 0);
    }

    /// A TOOL FAILURE OUTRANKS A FINDING: if the control did not pass, the
    /// findings of this run are not trustworthy either.
    #[test]
    fn a_tool_failure_outranks_a_finding() {
        let o = Outcome {
            checks: vec![check(Verdict::Dead, false)],
            tool_failures: vec!["control: `up` matched nothing".into()],
            ..Default::default()
        };
        assert_eq!(o.exit_code(), 2);
    }

    #[test]
    fn an_unused_exception_is_a_tool_failure() {
        let o = Outcome {
            tool_failures: vec!["unused exception: Weg".into()],
            ..Default::default()
        };
        assert_eq!(o.exit_code(), 2);
    }
}
