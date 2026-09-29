//! THE TEST THAT MAKES "0 DEAD RULES" WORTH ANYTHING: an instance that answers
//! `data: []` to everything must end in exit 2, never in a clean report.

use crosshair::config::Config;
use crosshair::http::{Canned, Http};
use crosshair::run::{Settings, run};
use serde_json::Value;
use std::cell::RefCell;

fn settings() -> Settings {
    settings_for(&["prometheus"])
}

fn settings_for(sources: &[&str]) -> Settings {
    Settings {
        prometheus: "http://x:9090".into(),
        loki: "http://x:3100".into(),
        loki_rules: None,
        grafana: "http://x:3000".into(),
        sources: sources.iter().map(|s| s.to_string()).collect(),
        long_secs: 604800,
        short_secs: 900,
        now: 1_000_000,
    }
}

#[test]
fn an_instance_that_answers_nothing_to_everything_is_a_tool_failure() {
    let h = Canned::new(vec![
        ("api/v1/series", r#"{"status":"success","data":[]}"#),
        (
            "api/v1/rules",
            r#"{"status":"success","data":{"groups":[]}}"#,
        ),
    ]);
    let o = run(&settings(), &Config::default(), &h, &h);
    assert_eq!(
        o.exit_code(),
        2,
        "a blind instance must not look like a clean run"
    );
    assert!(o.tool_failures.iter().any(|t| t.contains("control")));
}

#[test]
fn a_healthy_instance_with_one_dead_rule_is_exit_one() {
    let h = Canned::new(vec![
        // The control: `up` hits, the invented job does not.
        (
            "match%5B%5D=up%7Bjob%3D%22crosshair",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "match%5B%5D=up",
            r#"{"status":"success","data":[{"__name__":"up"}]}"#,
        ),
        (
            "match%5B%5D=gibtsnicht",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "api/v1/rules",
            r#"{"status":"success","data":{"groups":[{"name":"g","rules":[
            {"name":"TotesDing","type":"alerting","query":"gibtsnicht > 0","health":"ok","lastError":""}]}]}}"#,
        ),
    ]);
    let o = run(&settings(), &Config::default(), &h, &h);
    assert_eq!(o.exit_code(), 1);
}

/// A `Http` double that counts every `get()` whose URL contains `needle`,
/// wrapped around a `Canned` that answers as usual.
struct Counting<'a> {
    inner: &'a Canned,
    needle: &'a str,
    hits: RefCell<usize>,
}

impl Http for Counting<'_> {
    fn get(&self, url: &str) -> anyhow::Result<Value> {
        if url.contains(self.needle) {
            *self.hits.borrow_mut() += 1;
        }
        self.inner.get(url)
    }
    fn post(&self, url: &str, body: &str) -> anyhow::Result<Value> {
        self.inner.post(url, body)
    }
}

/// AUDIT (task-10): `run` caches the two window counts per selector so that
/// dashboards with hundreds of shared targets do not turn into twice as many
/// requests. Two rules that share ONE selector must ask Prometheus about it
/// exactly twice — long window, short window — never four times.
#[test]
fn two_rules_sharing_a_selector_ask_prometheus_only_twice() {
    let h = Canned::new(vec![
        (
            "match%5B%5D=up%7Bjob%3D%22crosshair",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "match%5B%5D=up",
            r#"{"status":"success","data":[{"__name__":"up"}]}"#,
        ),
        (
            "geteiltesding",
            r#"{"status":"success","data":[{"a":"b"}]}"#,
        ),
        (
            "api/v1/rules",
            r#"{"status":"success","data":{"groups":[{"name":"g","rules":[
            {"name":"Eins","type":"alerting","query":"geteiltesding > 0","health":"ok","lastError":""},
            {"name":"Zwei","type":"alerting","query":"geteiltesding > 1","health":"ok","lastError":""}]}]}}"#,
        ),
    ]);
    let counting = Counting {
        inner: &h,
        needle: "geteiltesding",
        hits: RefCell::new(0),
    };
    let o = run(&settings(), &Config::default(), &counting, &counting);
    assert_eq!(
        o.checks.len(),
        2,
        "both rules must produce a check for the shared selector: {:?}",
        o.checks
    );
    assert_eq!(
        *counting.hits.borrow(),
        2,
        "the selector cache must ask Prometheus once per window, not once per rule"
    );
}

// ---------------------------------------------------------------------------
// THE WIRING IN `run()` — the exceptions, the second control, and the
// backstop under a run that looked at nothing. All four were pinned only one
// level down (in `Config`, in `Prometheus`) until 0.1.1, and `run()` is where
// they change an exit code.
// ---------------------------------------------------------------------------

/// A Prometheus that is healthy, one rule whose selector is dead.
fn one_dead_rule() -> Canned {
    Canned::new(vec![
        (
            "match%5B%5D=up%7Bjob%3D%22crosshair",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "match%5B%5D=up",
            r#"{"status":"success","data":[{"__name__":"up"}]}"#,
        ),
        (
            "match%5B%5D=gibtsnicht",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "api/v1/rules",
            r#"{"status":"success","data":{"groups":[{"name":"g","rules":[
            {"name":"TotesDing","type":"alerting","query":"gibtsnicht > 0","health":"ok","lastError":""}]}]}}"#,
        ),
    ])
}

/// AN EXCEPTION TURNS EXIT 1 INTO EXIT 0, and that wiring lives in `run()`,
/// not in `Config`. `Config::covers` was pinned from the start; that `run()`
/// actually calls it, and only for a `Dead` verdict, was not.
#[test]
fn a_dead_selector_with_a_matching_exception_is_exit_zero() {
    let cfg: Config = toml::from_str(
        "[[exception]]\nrule = \"TotesDing\"\nreason = \"der Zaehler entsteht erst beim ersten Ereignis\"\n",
    )
    .unwrap();
    let h = one_dead_rule();
    let o = run(&settings(), &cfg, &h, &h);
    assert_eq!(
        o.exit_code(),
        0,
        "an excepted dead selector must not turn the run red: {:?}",
        o.tool_failures
    );
    assert_eq!(
        o.checks.iter().filter(|c| c.excepted).count(),
        1,
        "the check must be marked excepted, not merely ignored"
    );
}

/// AND THE STALENESS CHECK IS SKIPPED IN A NARROWED RUN, out loud. It asks
/// the whole file, and a run that looked at one source of three never even
/// visited the rules an entry for another source is about.
#[test]
fn a_narrowed_run_says_that_it_skipped_the_staleness_check() {
    let cfg: Config = toml::from_str(
        "[[exception]]\nrule = \"TotesDing\"\nreason = \"der Zaehler entsteht erst beim ersten Ereignis\"\n",
    )
    .unwrap();
    let h = one_dead_rule();
    let o = run(&settings(), &cfg, &h, &h);
    assert!(
        o.notes.iter().any(|n| n.contains("staleness check")),
        "a skipped check must be named, not silently omitted: {:?}",
        o.notes
    );
}

/// AN EXCEPTION THAT SUPPRESSED NOTHING TURNS THE RUN RED — pinned here
/// through `run()`, over a FULL run, because that is the only run in which
/// the question can be asked at all.
#[test]
fn a_full_run_whose_exception_matches_nothing_is_a_tool_failure() {
    let rules = std::env::temp_dir().join(format!("crosshair-blind-{}.yml", std::process::id()));
    std::fs::write(
        &rules,
        "groups:\n  - name: g\n    rules:\n      - alert: LokiOhneVps\n        expr: absent_over_time({gast=\"vps\"} [15m])\n",
    )
    .unwrap();
    let h = Canned::new(vec![
        // Both controls' impossible job, on either instance.
        (
            "crosshair-control-no-such-job",
            r#"{"status":"success","data":[]}"#,
        ),
        // Loki answers for its control AND for the rule's stream selector.
        (
            "loki/api/v1/series",
            r#"{"status":"success","data":[{"gast":"vps"}]}"#,
        ),
        (
            "query_range",
            r#"{"status":"success","data":{"result":[]}}"#,
        ),
        (
            "api/v1/rules",
            r#"{"status":"success","data":{"groups":[{"name":"g","rules":[
            {"name":"TotesDing","type":"alerting","query":"gibtsnicht > 0","health":"ok","lastError":""}]}]}}"#,
        ),
        (
            "match%5B%5D=gibtsnicht",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "api/v1/series",
            r#"{"status":"success","data":[{"__name__":"up"}]}"#,
        ),
        (
            "api/search",
            r#"[{"uid":"abc","folderTitle":"Observability","title":"Self"}]"#,
        ),
        (
            "api/dashboards/uid",
            r#"{"dashboard":{"panels":[{"type":"timeseries","title":"P",
            "datasource":{"uid":"prometheus"},"targets":[{"refId":"A","expr":"up"}]}]}}"#,
        ),
        (
            "api/ds/query",
            r#"{"results":{"Q0":{"frames":[{"data":{"values":[[1]]}}]},"Q1":{"frames":[]}}}"#,
        ),
    ]);
    let cfg: Config = toml::from_str(
        "[[exception]]\nrule = \"TotesDing\"\nreason = \"trifft noch\"\n\n[[exception]]\nrule = \"GibtsNichtMehr\"\nreason = \"hat seinen Befund ueberlebt\"\n",
    )
    .unwrap();
    let mut s = settings_for(&["prometheus", "loki", "grafana"]);
    s.loki_rules = Some(rules.clone());
    let o = run(&s, &cfg, &h, &h);
    let _ = std::fs::remove_file(&rules);
    assert!(
        o.tool_failures
            .iter()
            .any(|t| t.contains("exception matched nothing")),
        "a stale exception must be named: {:?} / {:?}",
        o.tool_failures,
        o.notes
    );
    assert_eq!(o.exit_code(), 2, "and it must turn the run red");
    assert_eq!(
        o.checks.iter().filter(|c| c.excepted).count(),
        1,
        "the OTHER exception still suppressed its finding"
    );
}

/// `health: unknown` MEANS "LOADED, NOT EVALUATED YET", and the maintenance
/// window runs crosshair right after the deploy that restarts obs-01. As a
/// finding it would abort the window on exit 1 for a rule that is merely
/// young.
#[test]
fn a_rule_prometheus_has_not_evaluated_yet_is_a_note_not_a_finding() {
    let h = Canned::new(vec![
        (
            "match%5B%5D=up%7Bjob%3D%22crosshair",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "api/v1/series",
            r#"{"status":"success","data":[{"__name__":"up"}]}"#,
        ),
        (
            "api/v1/rules",
            r#"{"status":"success","data":{"groups":[{"name":"g","rules":[
            {"name":"FrischDeployt","type":"alerting","query":"up > 0","health":"unknown","lastError":""}]}]}}"#,
        ),
    ]);
    let o = run(&settings(), &Config::default(), &h, &h);
    assert!(
        o.findings.is_empty(),
        "a rule that has not been evaluated yet is not a finding: {:?}",
        o.findings
    );
    assert!(
        o.notes.iter().any(|n| n.contains("not evaluated")),
        "but it must be named: {:?}",
        o.notes
    );
    assert_eq!(o.exit_code(), 0);
}

/// THE GRAFANA SOURCE HAS TWO LEGS AND NEEDS TWO CONTROLS. Every panel
/// verdict comes from `p.series()` straight against Prometheus; Grafana's own
/// control says nothing about that instance. A Prometheus answering
/// `data: []` to everything would otherwise make every panel look dead and
/// the run exit 1 — a hundred findings that are all an artefact.
#[test]
fn a_grafana_run_against_a_blind_prometheus_is_a_tool_failure() {
    let h = Canned::new(vec![
        (
            "api/ds/query",
            r#"{"results":{"Q0":{"frames":[{"data":{"values":[[1]]}}]},"Q1":{"frames":[]}}}"#,
        ),
        (
            "api/search",
            r#"[{"uid":"abc","folderTitle":"Observability","title":"Self"}]"#,
        ),
        (
            "api/dashboards/uid",
            r#"{"dashboard":{"panels":[{"type":"timeseries","title":"P",
            "datasource":{"uid":"prometheus"},"targets":[{"refId":"A","expr":"up"}]}]}}"#,
        ),
        ("api/v1/series", r#"{"status":"success","data":[]}"#),
    ]);
    let o = run(&settings_for(&["grafana"]), &Config::default(), &h, &h);
    assert!(
        o.tool_failures.iter().any(|t| t.contains("control")),
        "the prometheus control must run for the grafana source too: {:?} / checks {:?}",
        o.tool_failures,
        o.checks
    );
    assert_eq!(
        o.exit_code(),
        2,
        "a blind prometheus must not produce a page of dead panels"
    );
}

/// THE BACKSTOP. A run in which no source produced a single check has said
/// nothing — and an empty `Outcome` otherwise exits 0 under the sentence
/// "Every selector points at series that exist."
#[test]
fn a_run_whose_sources_produce_nothing_is_a_tool_failure() {
    let h = Canned::new(vec![("api/v1/series", r#"{"status":"success","data":[]}"#)]);
    let o = run(&settings_for(&[]), &Config::default(), &h, &h);
    assert_eq!(
        o.exit_code(),
        2,
        "a run that looked at nothing must not report success"
    );
    assert!(
        o.tool_failures
            .iter()
            .any(|t| t.contains("not a single selector")),
        "and it must say so: {:?}",
        o.tool_failures
    );
}

/// AUDIT B138 / CD-10: A PROMETHEUS THAT STOPPED INGESTING PASSED THE CONTROL.
/// `up` was asked over the long window only, and seven days of history still
/// answer there after the scrapes have stopped. Every selector then came back
/// `quiet` — hit long, empty short — and `quiet` never changes the exit code:
/// a deaf instance read as a calm week, exit 0.
///
/// `now` is 1_000_000, so the long window starts at 395200 and the short one
/// at 999100; the recorded answers tell them apart by `start=`.
#[test]
fn an_instance_with_up_only_in_the_long_window_is_a_tool_failure() {
    let h = Canned::new(vec![
        (
            "match%5B%5D=up%7Bjob%3D%22crosshair",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "match%5B%5D=up&start=395200",
            r#"{"status":"success","data":[{"__name__":"up"}]}"#,
        ),
        (
            "match%5B%5D=up&start=999100",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "match%5B%5D=wasdaswar&start=395200",
            r#"{"status":"success","data":[{"__name__":"wasdaswar"}]}"#,
        ),
        (
            "match%5B%5D=wasdaswar&start=999100",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "api/v1/rules",
            r#"{"status":"success","data":{"groups":[{"name":"g","rules":[
            {"name":"Verstummt","type":"alerting","query":"wasdaswar > 0","health":"ok","lastError":""}]}]}}"#,
        ),
    ]);
    let o = run(&settings(), &Config::default(), &h, &h);
    assert!(
        o.tool_failures
            .iter()
            .any(|t| t.contains("control") && t.contains("short window")),
        "a Prometheus with `up` only in the long window must fail the control: {:?} / checks {:?}",
        o.tool_failures,
        o.checks
    );
    assert_eq!(
        o.exit_code(),
        2,
        "a deaf instance must not look like a quiet week"
    );
}

/// THE SAME HOLE ON LOKI (audit B138 / CD-10): the journal stream asked over
/// the long window only still answers after Loki has stopped receiving lines.
/// Every stream selector then came back `quiet`, and the run exited 0.
///
/// In nanoseconds: the long window starts at 395200e9, the short one at
/// 999100e9.
#[test]
fn a_loki_with_the_journal_only_in_the_long_window_is_a_tool_failure() {
    let rules = std::env::temp_dir().join(format!(
        "crosshair-blind-loki-short-{}.yml",
        std::process::id()
    ));
    std::fs::write(
        &rules,
        "groups:\n  - name: g\n    rules:\n      - alert: Verstummt\n        expr: count_over_time({gast=\"stumm\"} [15m]) > 0\n",
    )
    .unwrap();
    let h = Canned::new(vec![
        (
            "crosshair-control-no-such-job",
            r#"{"status":"success","data":[]}"#,
        ),
        (
            "start=395200000000000",
            r#"{"status":"success","data":[{"job":"systemd-journal","gast":"stumm"}]}"#,
        ),
        ("start=999100000000000", r#"{"status":"success","data":[]}"#),
        (
            "query_range",
            r#"{"status":"success","data":{"result":[]}}"#,
        ),
    ]);
    let mut s = settings_for(&["loki"]);
    s.loki_rules = Some(rules.clone());
    let o = run(&s, &Config::default(), &h, &h);
    let _ = std::fs::remove_file(&rules);
    assert!(
        o.tool_failures
            .iter()
            .any(|t| t.contains("control") && t.contains("short window")),
        "a Loki with the journal only in the long window must fail the control: {:?} / checks {:?}",
        o.tool_failures,
        o.checks
    );
    assert_eq!(
        o.exit_code(),
        2,
        "a deaf Loki must not look like a quiet week"
    );
}
