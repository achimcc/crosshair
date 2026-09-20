//! THE TEST THAT MAKES "0 DEAD RULES" WORTH ANYTHING: an instance that answers
//! `data: []` to everything must end in exit 2, never in a clean report.

use crosshair::config::Config;
use crosshair::http::{Canned, Http};
use crosshair::run::{Settings, run};
use serde_json::Value;
use std::cell::RefCell;

fn settings() -> Settings {
    Settings {
        prometheus: "http://x:9090".into(),
        loki: "http://x:3100".into(),
        loki_rules: None,
        grafana: "http://x:3000".into(),
        grafana_password: None,
        sources: vec!["prometheus".into()],
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
