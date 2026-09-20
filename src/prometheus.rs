//! Prometheus: the rules it has REALLY loaded, and whether a selector points
//! at series it knows.
//!
//! THE RULES COME FROM THE INSTANCE, NOT FROM THE FILE (DEK-6): a rule file
//! Prometheus could not read does not appear here at all — and a check that
//! reads the source the checked value is derived from cannot go red.

use crate::http::{Http, percent_encode};
use anyhow::{Context, Result, bail};

/// One selector that must hit on any Prometheus, and one that must not.
pub const CONTROL_HIT: &str = "up";
pub const CONTROL_MISS: &str = r#"up{job="crosshair-control-no-such-job"}"#;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub kind: String,
    pub expr: String,
    pub health: String,
    pub last_error: String,
}

pub struct Prometheus<'a> {
    pub http: &'a dyn Http,
    pub base: String,
}

impl Prometheus<'_> {
    pub fn rules(&self) -> Result<Vec<Rule>> {
        let v = self.http.get(&format!("{}/api/v1/rules", self.base))?;
        if v["status"] != "success" {
            bail!("/api/v1/rules answered {}", v["status"]);
        }
        let mut out = Vec::new();
        for g in v["data"]["groups"].as_array().context("no groups")? {
            for r in g["rules"].as_array().context("a group without rules")? {
                out.push(Rule {
                    name: r["name"].as_str().unwrap_or_default().to_string(),
                    kind: r["type"].as_str().unwrap_or_default().to_string(),
                    expr: r["query"].as_str().unwrap_or_default().to_string(),
                    health: r["health"].as_str().unwrap_or_default().to_string(),
                    last_error: r["lastError"].as_str().unwrap_or_default().to_string(),
                });
            }
        }
        Ok(out)
    }

    /// How many series does this selector have in [start, end]?
    pub fn series(&self, selector: &str, start: i64, end: i64) -> Result<usize> {
        let url = format!(
            "{}/api/v1/series?match%5B%5D={}&start={start}&end={end}",
            self.base,
            percent_encode(selector)
        );
        let v = self.http.get(&url)?;
        if v["status"] != "success" {
            bail!("/api/v1/series answered {} for {selector}", v["status"]);
        }
        Ok(v["data"].as_array().context("no data array")?.len())
    }

    pub fn control(&self, start: i64, end: i64) -> Result<()> {
        if self.series(CONTROL_HIT, start, end)? == 0 {
            bail!(
                "control: `{CONTROL_HIT}` matched nothing — this run says NOTHING about the rules"
            );
        }
        if self.series(CONTROL_MISS, start, end)? != 0 {
            bail!("control: `{CONTROL_MISS}` matched although it cannot exist");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Canned;

    fn canned() -> Canned {
        Canned::new(vec![
            (
                "api/v1/rules",
                include_str!("../tests/fixtures/prometheus-rules.json"),
            ),
            (
                "api/v1/series",
                r#"{"status":"success","data":[{"__name__":"up"}]}"#,
            ),
        ])
    }

    #[test]
    fn rules_carry_expression_type_and_health() {
        let h = canned();
        let p = Prometheus {
            http: &h,
            base: "http://x:9090".into(),
        };
        let r = p.rules().unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].name, "InsistSendetNicht");
        assert_eq!(r[0].expr, "insist_publish_pending > 0");
        // A RECORDING RULE POINTING AT NOTHING IS JUST AS DEAD as an alerting
        // one, so it is not filtered out.
        assert_eq!(r[1].kind, "recording");
        assert_eq!(r[2].health, "err");
        assert_eq!(r[2].last_error, "vector cannot contain metrics");
    }

    #[test]
    fn series_counts_the_data_array() {
        let h = canned();
        let p = Prometheus {
            http: &h,
            base: "http://x:9090".into(),
        };
        assert_eq!(p.series("up", 0, 1).unwrap(), 1);
    }

    /// NOT A FINDING BUT A TOOL FAILURE: an answer that is not `success` says
    /// nothing about the rules. The bash version got this right and it is the
    /// reason it never declared 33 rules broken because Prometheus was down.
    ///
    /// THE `data` FIELD IS PART OF THE TEST, not decoration: without it the
    /// test also passes when the status check is gone, because the missing
    /// array raises its own error — a test that passes for the wrong reason.
    #[test]
    fn an_unsuccessful_answer_is_an_error() {
        let h = Canned::new(vec![(
            "api/v1/series",
            r#"{"status":"error","errorType":"bad_data","error":"bad","data":[]}"#,
        )]);
        let p = Prometheus {
            http: &h,
            base: "http://x:9090".into(),
        };
        assert!(p.series("up", 0, 1).is_err());
    }

    /// Same tool-failure-not-a-finding rule as `series()`, and the same trap:
    /// the `data` field must be present and well-formed (`groups: []`), or the
    /// missing/malformed array raises its own error and the test passes for
    /// the wrong reason even with the status check gone.
    #[test]
    fn an_unsuccessful_rules_answer_is_an_error() {
        let h = Canned::new(vec![(
            "api/v1/rules",
            r#"{"status":"error","error":"bad","data":{"groups":[]}}"#,
        )]);
        let p = Prometheus {
            http: &h,
            base: "http://x:9090".into(),
        };
        assert!(p.rules().is_err());
    }

    /// The positive control: one selector that MUST hit and one that must NOT.
    #[test]
    fn the_control_passes_when_up_hits_and_the_invented_job_does_not() {
        let h = Canned::new(vec![
            ("match%5B%5D=up%7Bjob", r#"{"status":"success","data":[]}"#),
            (
                "api/v1/series",
                r#"{"status":"success","data":[{"__name__":"up"}]}"#,
            ),
        ]);
        let p = Prometheus {
            http: &h,
            base: "http://x:9090".into(),
        };
        assert!(p.control(0, 1).is_ok());
    }

    /// An instance that answers `data: []` to EVERYTHING must fail the control
    /// — otherwise "0 dead rules" and "the query went nowhere" look the same.
    #[test]
    fn a_blind_instance_fails_the_control() {
        let h = Canned::new(vec![("api/v1/series", r#"{"status":"success","data":[]}"#)]);
        let p = Prometheus {
            http: &h,
            base: "http://x:9090".into(),
        };
        assert!(p.control(0, 1).is_err());
    }

    /// And the other direction: an instance that answers "hit" to everything
    /// is just as broken, and much easier to overlook.
    #[test]
    fn an_instance_that_matches_everything_fails_the_control() {
        let h = Canned::new(vec![(
            "api/v1/series",
            r#"{"status":"success","data":[{"a":"b"}]}"#,
        )]);
        let p = Prometheus {
            http: &h,
            base: "http://x:9090".into(),
        };
        assert!(p.control(0, 1).is_err());
    }
}
