//! Grafana: the dashboards it really serves, and the expressions of their
//! panels — asked THROUGH Grafana, never straight at Prometheus.
//!
//! WHY THROUGH GRAFANA: if a panel's `datasource.uid` is wrong, the panel
//! shows "Datasource not found" while the very same expression answers fine
//! against Prometheus. Only the way through `/api/ds/query` measures both at
//! once.
//!
//! WHY FROM GRAFANA AND NOT FROM THE REPO FILES: same rule as everywhere,
//! read the finished result. A dashboard the provisioner never applied does
//! not appear here — and that is a statement one wants to see.

use crate::http::Http;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

pub const CONTROL_HIT: &str = "up";
pub const CONTROL_MISS: &str = r#"up{job="crosshair-control-no-such-job"}"#;

#[derive(Debug, Clone)]
pub struct Target {
    pub panel: String,
    pub refid: String,
    pub expr: String,
    pub datasource: String,
}

#[derive(Debug, Clone)]
pub enum Skip {
    OtherDatasource(String),
    UnresolvedVariable,
}

#[derive(Debug, Clone)]
pub enum QueryOutcome {
    Series(usize),
    Error(String),
}

/// Every Prometheus target of a dashboard, plus the ones left out and why.
pub fn targets(doc: &Value) -> (Vec<Target>, Vec<(String, Skip)>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let root = if doc.get("dashboard").is_some() {
        &doc["dashboard"]
    } else {
        doc
    };
    walk(root, &mut |panel: &Value| {
        let title = panel["title"]
            .as_str()
            .unwrap_or("(ohne Titel)")
            .to_string();
        let panel_ds = panel["datasource"]["uid"]
            .as_str()
            .unwrap_or("")
            .to_string();
        for t in panel["targets"].as_array().into_iter().flatten() {
            let Some(expr) = t["expr"].as_str().filter(|e| !e.is_empty()) else {
                continue;
            };
            let refid = t["refId"].as_str().unwrap_or("?").to_string();
            let ds = t["datasource"]["uid"]
                .as_str()
                .unwrap_or(&panel_ds)
                .to_string();
            if ds != "prometheus" {
                skipped.push((refid, Skip::OtherDatasource(ds)));
                continue;
            }
            let resolved = expr
                .replace("$__rate_interval", "5m")
                .replace("$__range", "24h")
                .replace("$__interval", "1m");
            if resolved.contains('$') {
                skipped.push((refid, Skip::UnresolvedVariable));
                continue;
            }
            out.push(Target {
                panel: title.clone(),
                refid,
                expr: resolved,
                datasource: ds,
            });
        }
    });
    (out, skipped)
}

/// Every object that has `targets` and a `type` other than `row` — including
/// the ones nested under a collapsed row.
fn walk(v: &Value, f: &mut impl FnMut(&Value)) {
    match v {
        Value::Object(map) => {
            if map.contains_key("targets")
                && map.get("type").and_then(|t| t.as_str()) != Some("row")
            {
                f(v);
            }
            for child in map.values() {
                walk(child, f);
            }
        }
        Value::Array(items) => {
            for child in items {
                walk(child, f);
            }
        }
        _ => {}
    }
}

pub struct Grafana<'a> {
    pub http: &'a dyn Http,
    pub base: String,
}

impl Grafana<'_> {
    /// THROUGH THE LOGIN FORM: `auth.basic.enabled = false` on this
    /// installation, so `curl -u` gets a 401. The password travels in the
    /// body, which goes over stdin — never argv.
    ///
    /// AND IT FAILS CLOSED. An earlier draft also accepted an answer with no
    /// `message` field at all, on the reasoning that `curl --fail` would have
    /// turned any non-2xx into an error before we got here. That reasoning is
    /// unfalsifiable and buys nothing: anything that answers 200 with an
    /// unexpected body — a proxy, a cache, a future Grafana — would then be
    /// reported as a session we do not have.
    pub fn login(&self, password: &str) -> Result<()> {
        let body = json!({ "user": "admin", "password": password }).to_string();
        let v = self.http.post(&format!("{}/login", self.base), &body)?;
        if v["message"].as_str() == Some("Logged in") {
            return Ok(());
        }
        bail!("grafana did not confirm the login: {}", v["message"]);
    }

    pub fn dashboards(&self) -> Result<Vec<(String, String)>> {
        let v = self
            .http
            .get(&format!("{}/api/search?type=dash-db&limit=5000", self.base))?;
        let arr = v
            .as_array()
            .context("/api/search did not answer an array")?;
        Ok(arr
            .iter()
            .filter_map(|d| {
                let uid = d["uid"].as_str()?.to_string();
                let folder = d["folderTitle"].as_str().unwrap_or("");
                let title = d["title"].as_str().unwrap_or("");
                Some((uid, format!("{folder}/{title}")))
            })
            .collect())
    }

    pub fn dashboard(&self, uid: &str) -> Result<Value> {
        self.http
            .get(&format!("{}/api/dashboards/uid/{uid}", self.base))
    }

    /// One request for a batch of expressions; the answers keep their order
    /// through the `Q<i>` refIds.
    pub fn query(&self, exprs: &[String]) -> Result<Vec<QueryOutcome>> {
        let queries: Vec<Value> = exprs
            .iter()
            .enumerate()
            .map(|(i, e)| {
                json!({
                    "refId": format!("Q{i}"),
                    "datasource": { "type": "prometheus", "uid": "prometheus" },
                    "expr": e,
                    "instant": true
                })
            })
            .collect();
        let body = json!({ "from": "now-24h", "to": "now", "queries": queries }).to_string();
        let v = self
            .http
            .post(&format!("{}/api/ds/query", self.base), &body)?;
        let results = v
            .get("results")
            .context("an answer without results is not a check, it is its failure")?;
        let mut out = Vec::new();
        for i in 0..exprs.len() {
            let a = &results[format!("Q{i}")];
            if let Some(e) = a["error"].as_str() {
                out.push(QueryOutcome::Error(e.to_string()));
                continue;
            }
            let series: usize = a["frames"]
                .as_array()
                .map(|fr| {
                    fr.iter()
                        .map(|f| f["data"]["values"][0].as_array().map_or(0, |v| v.len()))
                        .sum()
                })
                .unwrap_or(0);
            out.push(QueryOutcome::Series(series));
        }
        Ok(out)
    }

    pub fn control(&self) -> Result<()> {
        let r = self.query(&[CONTROL_HIT.to_string(), CONTROL_MISS.to_string()])?;
        match (&r[0], &r[1]) {
            (QueryOutcome::Series(n), QueryOutcome::Series(0)) if *n > 0 => Ok(()),
            (a, b) => {
                bail!("grafana control failed: `{CONTROL_HIT}` -> {a:?}, `{CONTROL_MISS}` -> {b:?}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Canned;

    fn dash() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/dashboard.json")).unwrap()
    }

    /// A panel inside a COLLAPSED ROW sits under `.panels` of a row panel. The
    /// bash version walks `..` for exactly this reason.
    #[test]
    fn a_target_inside_a_collapsed_row_is_found() {
        let (t, _) = targets(&dash());
        assert!(t.iter().any(|x| x.refid == "B" && x.panel == "In der Row"));
    }

    /// The known Grafana macros are resolved, as the bash version does — 5m,
    /// 24h, 1m.
    #[test]
    fn grafana_macros_are_resolved() {
        let (t, _) = targets(&dash());
        let a = t.iter().find(|x| x.refid == "A").unwrap();
        assert_eq!(a.expr, "sum(rate(radarr_movie_total[5m]))");
    }

    /// SKIPPED IS NAMED, NOT DROPPED: leaving something out must be
    /// distinguishable from forgetting it.
    #[test]
    fn a_dashboard_variable_makes_a_target_skipped_with_a_reason() {
        let (t, skipped) = targets(&dash());
        assert!(!t.iter().any(|x| x.refid == "D"));
        assert!(
            skipped
                .iter()
                .any(|(r, s)| r == "D" && matches!(s, Skip::UnresolvedVariable))
        );
    }

    #[test]
    fn a_foreign_datasource_is_skipped_with_its_name() {
        let (_, skipped) = targets(&dash());
        assert!(
            skipped
                .iter()
                .any(|(r, s)| r == "C" && matches!(s, Skip::OtherDatasource(d) if d == "loki"))
        );
    }

    /// THE QUESTION GOES THROUGH GRAFANA AND NOT STRAIGHT TO PROMETHEUS, and
    /// that is the whole point of this adapter: a wrong `datasource.uid` shows
    /// "Datasource not found" while the same expression answers fine against
    /// Prometheus.
    #[test]
    fn an_error_from_grafana_is_told_apart_from_an_empty_result() {
        let h = Canned::new(vec![(
            "api/ds/query",
            r#"{"results":{
            "Q0":{"frames":[{"data":{"values":[[1,2],[3,4]]}}]},
            "Q1":{"frames":[]},
            "Q2":{"error":"Datasource not found"}}}"#,
        )]);
        let g = Grafana {
            http: &h,
            base: "http://127.0.0.1:3000".into(),
        };
        let r = g.query(&["a".into(), "b".into(), "c".into()]).unwrap();
        assert!(matches!(r[0], QueryOutcome::Series(2)));
        assert!(matches!(r[1], QueryOutcome::Series(0)));
        assert!(matches!(&r[2], QueryOutcome::Error(e) if e.contains("Datasource not found")));
    }

    #[test]
    fn a_login_that_is_refused_is_an_error() {
        let h = Canned::new(vec![(
            "login",
            r#"{"message":"Invalid username or password"}"#,
        )]);
        let g = Grafana {
            http: &h,
            base: "http://127.0.0.1:3000".into(),
        };
        assert!(g.login("wrong").is_err());
    }

    /// A 200 with a body that does not confirm the login is NOT a session.
    /// `Canned` has no HTTP status, which is the point: it stands in for
    /// every intermediary that answers cheerfully without logging anyone in.
    #[test]
    fn a_login_answer_without_a_confirmation_is_an_error() {
        let h = Canned::new(vec![("login", "{}")]);
        let g = Grafana {
            http: &h,
            base: "http://127.0.0.1:3000".into(),
        };
        assert!(
            g.login("whatever").is_err(),
            "a message-less answer must not count as a session"
        );
    }

    #[test]
    fn the_confirmed_login_is_accepted() {
        let h = Canned::new(vec![("login", r#"{"message":"Logged in"}"#)]);
        let g = Grafana {
            http: &h,
            base: "http://127.0.0.1:3000".into(),
        };
        assert!(g.login("right").is_ok());
    }

    /// AUDIT (task-8): a frame that carries no series at all — an empty
    /// `values` array, or no `data` key whatsoever — counts as zero rather
    /// than panicking. Grafana's own `/api/ds/query` answers exactly this
    /// shape for an expression that is syntactically fine but matches
    /// nothing, and that is the common case, not the exotic one.
    #[test]
    fn a_frame_without_series_counts_as_zero_not_a_panic() {
        let h = Canned::new(vec![(
            "api/ds/query",
            r#"{"results":{
            "Q0":{"frames":[{"data":{"values":[]}}]},
            "Q1":{"frames":[{}]}}}"#,
        )]);
        let g = Grafana {
            http: &h,
            base: "http://127.0.0.1:3000".into(),
        };
        let r = g.query(&["a".into(), "b".into()]).unwrap();
        assert!(matches!(r[0], QueryOutcome::Series(0)));
        assert!(matches!(r[1], QueryOutcome::Series(0)));
    }

    /// AUDIT (task-8): a Grafana that answers ONE SERIES TO EVERYTHING —
    /// including the control's own impossible job — is exactly as broken as
    /// a silent Prometheus datasource, and `control` must say so.
    #[test]
    fn control_fails_when_the_miss_also_answers_a_series() {
        let h = Canned::new(vec![(
            "api/ds/query",
            r#"{"results":{
            "Q0":{"frames":[{"data":{"values":[[1]]}}]},
            "Q1":{"frames":[{"data":{"values":[[1]]}}]}}}"#,
        )]);
        let g = Grafana {
            http: &h,
            base: "http://127.0.0.1:3000".into(),
        };
        assert!(g.control().is_err());
    }

    /// AUDIT (task-8): and a Grafana that answers NOTHING TO EVERYTHING —
    /// including the control's own known-good `up` — is just as broken, the
    /// other direction of the same check.
    #[test]
    fn control_fails_when_the_hit_answers_nothing() {
        let h = Canned::new(vec![(
            "api/ds/query",
            r#"{"results":{
            "Q0":{"frames":[]},
            "Q1":{"frames":[]}}}"#,
        )]);
        let g = Grafana {
            http: &h,
            base: "http://127.0.0.1:3000".into(),
        };
        assert!(g.control().is_err());
    }
}
