//! Loki: the rules from the YAML, the streams from the instance.
//!
//! WHY THE YAML AND NOT THE RULER API — and this is measured, not assumed: on
//! this installation `/loki/api/v1/rules`, `/prometheus/api/v1/rules` and
//! `/api/prom/rules` all answer 404 (2026-09-20). This is the one place where
//! "read the finished result" does not hold, and it is NAMED rather than
//! quietly broken: a rule checked here may be one Loki never loaded.
//! `lokitool rules check` covers that half and stays in the maintenance window.

use crate::http::{Http, percent_encode};
use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const CONTROL_HIT: &str = r#"{job="systemd-journal"}"#;
pub const CONTROL_MISS: &str = r#"{job="crosshair-control-no-such-job"}"#;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub expr: String,
}

#[derive(Deserialize)]
struct File {
    groups: Vec<Group>,
}
#[derive(Deserialize)]
struct Group {
    rules: Vec<YamlRule>,
}
#[derive(Deserialize)]
struct YamlRule {
    alert: Option<String>,
    record: Option<String>,
    expr: String,
}

pub fn rules_from_yaml(text: &str) -> Result<Vec<Rule>> {
    let f: File = serde_norway::from_str(text).context("parsing the rule file")?;
    let out: Vec<Rule> = f
        .groups
        .into_iter()
        .flat_map(|g| g.rules)
        .map(|r| Rule {
            name: r.alert.or(r.record).unwrap_or_else(|| "(unnamed)".into()),
            expr: r.expr,
        })
        .collect();
    if out.is_empty() {
        bail!(
            "the rule file holds not a single rule — that is not a green run, it is an empty one"
        );
    }
    Ok(out)
}

pub struct Loki<'a> {
    pub http: &'a dyn Http,
    pub base: String,
}

impl Loki<'_> {
    pub fn series(&self, selector: &str, start_ns: i64, end_ns: i64) -> Result<usize> {
        let url = format!(
            "{}/loki/api/v1/series?match%5B%5D={}&start={start_ns}&end={end_ns}",
            self.base,
            percent_encode(selector)
        );
        let v = self.http.get(&url)?;
        if v["status"] != "success" {
            bail!(
                "/loki/api/v1/series answered {} for {selector}",
                v["status"]
            );
        }
        Ok(v["data"].as_array().context("no data array")?.len())
    }

    /// Does Loki evaluate the whole expression? `Ok(None)` = yes.
    ///
    /// `query_range` AND NOT `query`: an expression without aggregation is a
    /// LOG query for Loki, and the instant endpoint refuses those — "log
    /// queries are not supported as an instant query type".
    pub fn evaluates(&self, expr: &str, start_ns: i64, end_ns: i64) -> Result<Option<String>> {
        let url = format!(
            "{}/loki/api/v1/query_range?query={}&start={start_ns}&end={end_ns}&limit=1",
            self.base,
            percent_encode(expr)
        );
        // A refused expression makes curl --fail exit non-zero, so the reason
        // arrives as an error here. That is a finding about the rule, not a
        // tool failure — unless we cannot tell, and then it stays an error.
        match self.http.get(&url) {
            Ok(v) => {
                if v["status"] == "success" {
                    Ok(None)
                } else {
                    Ok(Some(
                        v["error"].as_str().unwrap_or("no reason given").to_string(),
                    ))
                }
            }
            Err(e) => {
                // CLASSIFY BY THE EXIT CODE, NOT BY A PHRASE IN THE MESSAGE.
                // `curl --fail` exits 22 — and only 22 — when the server
                // answered >= 400, which is how Loki refuses an expression.
                // Every other code is about the transport: 7 could not
                // connect, 28 timed out, 6 could not resolve the host. A
                // message that merely CONTAINS "400" says nothing; a
                // load balancer's error text would otherwise be reported as a
                // finding about the rule and hide a broken tunnel.
                //
                // Over ssh the remote curl's status comes back as ssh's own,
                // so the marker is the same on both routes.
                let text = e.to_string();
                if text.contains("exit status: 22") {
                    Ok(Some(text.chars().take(160).collect()))
                } else {
                    Err(e)
                }
            }
        }
    }

    /// The journal stream must hit in BOTH windows, the invented job in
    /// neither.
    ///
    /// WHY THE SHORT WINDOW TOO — the same hole `Prometheus::control` had
    /// (audit B138 / CD-10): over the long window alone, a Loki that stopped
    /// receiving lines yesterday still shows seven days of the journal stream.
    /// The control passed, every stream selector came back `quiet`, and
    /// `quiet` changes no exit code — a deaf Loki read as a calm week.
    pub fn control(&self, long_start_ns: i64, short_start_ns: i64, end_ns: i64) -> Result<()> {
        if self.series(CONTROL_HIT, long_start_ns, end_ns)? == 0 {
            bail!(
                "control: `{CONTROL_HIT}` matched nothing — this run says NOTHING about the rules"
            );
        }
        if self.series(CONTROL_HIT, short_start_ns, end_ns)? == 0 {
            bail!(
                "control: `{CONTROL_HIT}` matched nothing in the short window — the instance is not ingesting, and every `quiet` verdict of this run would be its artefact"
            );
        }
        if self.series(CONTROL_MISS, long_start_ns, end_ns)? != 0 {
            bail!("control: `{CONTROL_MISS}` matched although it cannot exist");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Canned;

    const YAML: &str = r#"
groups:
  - name: zugriff
    rules:
      - alert: ZugriffslogVersiegt
        expr: |
          absent_over_time({gast="infra-01", unit="caddy.service"} |= "handled request" [15m])
        for: 15m
      - alert: LokiOhneVps
        expr: absent_over_time({gast="vps"} [15m])
"#;

    /// THE EXPRESSIONS COME FROM A PARSER, NOT FROM A SEARCH PATTERN: a `grep`
    /// over `expr:` finds its hit in a file that is unreadable AS A WHOLE —
    /// the lesson from `blueprints-pruefen.py` (2026-09-06).
    #[test]
    fn rules_come_out_of_the_yaml_with_their_expressions() {
        let r = rules_from_yaml(YAML).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].name, "ZugriffslogVersiegt");
        assert!(
            r[0].expr
                .contains(r#"{gast="infra-01", unit="caddy.service"}"#)
        );
        assert_eq!(r[1].name, "LokiOhneVps");
    }

    #[test]
    fn broken_yaml_is_an_error_not_an_empty_list() {
        assert!(rules_from_yaml("groups: [ {").is_err());
    }

    /// A FILE WITHOUT A SINGLE RULE IS NOT A GREEN RUN, IT IS AN EMPTY ONE —
    /// the bash version says exactly this and it is worth keeping.
    #[test]
    fn a_file_without_rules_is_an_error() {
        assert!(rules_from_yaml("groups: []").is_err());
    }

    #[test]
    fn series_counts_the_data_array() {
        let h = Canned::new(vec![(
            "loki/api/v1/series",
            r#"{"status":"success","data":[{"gast":"vps"}]}"#,
        )]);
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert_eq!(l.series(r#"{gast="vps"}"#, 0, 1).unwrap(), 1);
    }

    /// NOT A FINDING BUT A TOOL FAILURE: an answer that is not `success` says
    /// nothing about the rules. THE `data` FIELD IS PART OF THE TEST, not
    /// decoration (same trap as in `prometheus.rs`): without it the test also
    /// passes when the status check is gone, because the missing array raises
    /// its own error — a test that passes for the wrong reason. Added during
    /// the mutation audit of this task: the brief's own fixture set left this
    /// check unpinned.
    #[test]
    fn an_unsuccessful_series_answer_is_an_error() {
        let h = Canned::new(vec![(
            "loki/api/v1/series",
            r#"{"status":"error","error":"bad","data":[]}"#,
        )]);
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(l.series(r#"{gast="vps"}"#, 0, 1).is_err());
    }

    /// The addition to the design: the FULL expression is put as well, because
    /// `lokitool rules check` only sees syntax. An expression Loki refuses is a
    /// finding about the RULE.
    ///
    /// THIS EXERCISES THE `Ok(v)` BRANCH — a Loki that answers 200 with a
    /// `"status":"error"` body. That is real too, but it is not how `curl
    /// --fail` actually reports a refusal; see
    /// `a_refusal_arriving_as_an_exit_22_is_a_finding` below for the path the
    /// module doc describes.
    #[test]
    fn an_expression_loki_refuses_is_reported_as_a_finding() {
        let h = Canned::new(vec![(
            "query_range",
            r#"{"status":"error","error":"parse error at line 1"}"#,
        )]);
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        let r = l.evaluates("{gast=\"vps\"} | json", 0, 1).unwrap();
        assert!(r.unwrap().contains("parse error"));
    }

    /// An `Http` that fails the way `Curl` fails, with a text we choose.
    struct Failing(String);
    impl Http for Failing {
        fn get(&self, _url: &str) -> anyhow::Result<serde_json::Value> {
            anyhow::bail!("{}", self.0)
        }
        fn post(&self, _url: &str, _body: &str) -> anyhow::Result<serde_json::Value> {
            anyhow::bail!("{}", self.0)
        }
    }

    /// THE REAL PATH: curl --fail exits 22 on a 4xx, so a refused expression
    /// reaches us as an Err — and it must come back out as a FINDING.
    #[test]
    fn a_refusal_arriving_as_an_exit_22_is_a_finding() {
        let h = Failing(
            "curl failed (exit status: 22): curl: (22) The requested URL returned error: 400"
                .into(),
        );
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(
            l.evaluates(r#"{gast="vps"} | json"#, 0, 1)
                .unwrap()
                .is_some()
        );
    }

    /// And the same over ssh, where the remote curl's code arrives as ssh's.
    #[test]
    fn a_refusal_over_ssh_is_a_finding_too() {
        let h = Failing("ssh failed (exit status: 22): curl: (22) …".into());
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(l.evaluates(r#"{gast="vps"}"#, 0, 1).unwrap().is_some());
    }

    /// A DEAD TUNNEL IS NOT A FINDING ABOUT THE RULE. curl exits 7 when it
    /// cannot connect; reporting that as "Loki refuses the expression" would
    /// hide the outage behind a rule complaint.
    #[test]
    fn a_transport_failure_stays_a_tool_failure() {
        let h = Failing("curl failed (exit status: 7): curl: (7) Failed to connect".into());
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(l.evaluates(r#"{gast="vps"}"#, 0, 1).is_err());
    }

    /// And a number in prose is not an exit code: an error text that merely
    /// mentions 400 must stay a tool failure.
    #[test]
    fn the_digits_400_in_a_message_do_not_make_a_finding() {
        let h =
            Failing("curl failed (exit status: 7): read 400 bytes, then the peer went away".into());
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(l.evaluates(r#"{gast="vps"}"#, 0, 1).is_err());
    }

    #[test]
    fn an_expression_loki_evaluates_is_no_finding() {
        let h = Canned::new(vec![(
            "query_range",
            r#"{"status":"success","data":{"result":[]}}"#,
        )]);
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert_eq!(l.evaluates(r#"{gast="vps"}"#, 0, 1).unwrap(), None);
    }

    /// AND AN ANSWER THAT IS NOT JSON AT ALL is the third case, and the bash
    /// version learned it the hard way on 2026-09-12: Loki answered a log query
    /// on the instant endpoint with plain text, the script counted zero lines
    /// and declared all ten rules dead. `Canned` raises here, and the error
    /// must travel as an error, not as "refused".
    #[test]
    fn a_non_json_answer_is_a_tool_failure() {
        let h = Canned::new(vec![("something-else", "{}")]);
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(l.evaluates(r#"{gast="vps"}"#, 0, 1).is_err());
    }

    #[test]
    fn a_blind_instance_fails_the_control() {
        let h = Canned::new(vec![(
            "loki/api/v1/series",
            r#"{"status":"success","data":[]}"#,
        )]);
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(l.control(0, 0, 1).is_err());
    }

    /// And the other direction, the one that is much easier to overlook: an
    /// instance that answers a stream to EVERYTHING — including the job name
    /// invented for this control — is just as broken. Prometheus and Grafana
    /// each pin both directions; this is Loki's.
    #[test]
    fn an_instance_that_matches_everything_fails_the_control() {
        let h = Canned::new(vec![(
            "loki/api/v1/series",
            r#"{"status":"success","data":[{"gast":"vps"}]}"#,
        )]);
        let l = Loki {
            http: &h,
            base: "http://x:3100".into(),
        };
        assert!(l.control(0, 0, 1).is_err());
    }
}
