//! Real expressions from the homeserver repo. Measured on 2026-09-20: 72 rules
//! in obs-regeln.yml parse without a single error, 95 distinct selectors, 15
//! rules with more than one, exactly one rule without any (`Watchdog: vector(1)`).
//! (An earlier throwaway probe reported 101/16 by counting every selector
//! *occurrence* rather than deduplicating within one expression — see the
//! comment on `obs_regeln_yml_matches_the_2026_09_20_measurement` below.)

use crosshair::{logql, promql};

#[test]
fn the_two_selector_case_from_2026_09_06() {
    let s =
        promql::selectors("radarr_movie_filesize_total + sonarr_series_filesize_bytes").unwrap();
    assert_eq!(
        s.len(),
        2,
        "one of the two summands was enough to empty the panel"
    );
}

#[test]
fn the_absent_shape_that_must_not_need_an_exception() {
    let s = promql::selectors(r#"up{job="insist"} == 0 or absent(up{job="insist"})"#).unwrap();
    assert_eq!(s, vec![r#"up{job="insist"}"#]);
}

#[test]
fn the_textfile_freshness_shape_with_its_escaped_regex() {
    let src = r#"time() - node_textfile_mtime_seconds{file=~".*/gast-speicher\\.prom"} > 1800"#;
    let s = promql::selectors(src).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(
        promql_parser::parser::parse(&s[0]).unwrap(),
        promql_parser::parser::parse(
            r#"node_textfile_mtime_seconds{file=~".*/gast-speicher\\.prom"}"#
        )
        .unwrap()
    );
}

#[test]
fn the_deadman_has_no_selector_and_that_is_not_a_finding() {
    assert!(promql::selectors("vector(1)").unwrap().is_empty());
}

#[test]
fn audit_spur_ohne_deploy_names_two_streams_and_repeats_neither() {
    let e = r#"sum by (schluessel) (count_over_time({gast="server", job="systemd-journal"} |~ `key="(rechte|zugang|einheiten)"` | regexp `key="(?P<schluessel>[a-z]+)"` [15m])) unless on() sum(count_over_time({gast="server", job="systemd-journal"} |~ `switch-to-configuration|Linux version [0-9]` [30m]))"#;
    assert_eq!(
        logql::stream_selectors(e),
        vec![r#"{gast="server", job="systemd-journal"}"#]
    );
}

// --- Piece 2: the counting probe over the real rule files -----------------
//
// The path lives OUTSIDE this repo (a sibling checkout of the homeserver
// monorepo) — a clone of crosshair anywhere else has no such neighbour. Both
// tests below skip with a printed note rather than fail when the file is
// missing; run them explicitly with `cargo test --test rules -- --ignored`.

const OBS_REGELN: &str = "/home/achim/Projects/homeserver/.claude/worktrees/leakwatch/hosts/server/gaeste/obs-regeln.yml";
const LOKI_REGELN: &str = "/home/achim/Projects/homeserver/.claude/worktrees/leakwatch/hosts/server/gaeste/loki-regeln.yml";

// MEASURED 2026-09-20, corrected 2026-09-20 after the first real run of
// this test: 72 rules, 0 parse errors, 95 DISTINCT selectors, 15 rules
// with more than one, exactly one rule with none (`Watchdog: vector(1)`).
//
// The design notes say 101 and 16. Those count OCCURRENCES: the throwaway
// probe that produced them pushed every vector selector it visited, while
// `promql::selectors` collapses repeats within one expression — which is
// the documented behaviour and has its own test
// (`duplicates_within_one_expression_collapse` in `src/promql.rs`), and the
// same design point as `the_absent_shape_that_must_not_need_an_exception`
// above, which pins this exact behaviour for the real rule
// `InsistNichtErreichbar`. Four rules carry the difference, each naming the
// same selector twice or more within one expression: `InsistNichtErreichbar`
// (2 occurrences -> 1 distinct, the one rule that leaves the ">1" bucket),
// `RustsecNeueMeldung` (3 -> 2, `rustsec_meldung` named twice — once plain,
// once with `offset 2d`), `ProwlarrIndexerFailing` (3 -> 2), `ArrNoImports`
// (9 -> 6). 95 is the number that costs something: it is how many series
// queries a run actually puts to Prometheus, which is what the cache in
// `run()` is for.
#[test]
#[ignore = "reads a file outside this repo; run with --ignored"]
fn obs_regeln_yml_matches_the_2026_09_20_measurement() {
    let Ok(text) = std::fs::read_to_string(OBS_REGELN) else {
        eprintln!("skip: {OBS_REGELN} not present — no monitoring repo next to this checkout");
        return;
    };

    let rules = crosshair::loki::rules_from_yaml(&text).expect("obs-regeln.yml must parse as YAML");

    let mut parse_errors = 0usize;
    let mut total_selectors = 0usize;
    let mut more_than_one = 0usize;
    let mut none_at_all = 0usize;

    for rule in &rules {
        match promql::selectors(&rule.expr) {
            Ok(sel) => {
                total_selectors += sel.len();
                if sel.len() > 1 {
                    more_than_one += 1;
                }
                if sel.is_empty() {
                    none_at_all += 1;
                }
            }
            Err(e) => {
                parse_errors += 1;
                eprintln!("parse error in {}: {e}", rule.name);
            }
        }
    }

    eprintln!(
        "obs-regeln.yml: {} rules, {parse_errors} parse errors, {total_selectors} selectors, \
         {more_than_one} with more than one, {none_at_all} with none",
        rules.len()
    );

    assert_eq!(
        rules.len(),
        72,
        "rule count drifted from the 2026-09-20 measurement"
    );
    assert_eq!(
        parse_errors, 0,
        "a PromQL expression in obs-regeln.yml no longer parses"
    );
    assert_eq!(
        total_selectors, 95,
        "total distinct selector count drifted from the 2026-09-20 measurement"
    );
    assert_eq!(
        more_than_one, 15,
        "count of rules with more than one distinct selector drifted"
    );
    assert_eq!(
        none_at_all, 1,
        "count of rules with no selector drifted (expected only Watchdog)"
    );
}

/// Measured 2026-09-20: 16 rules in loki-regeln.yml, of which 14 carry one
/// `{…}` brace block, one carries two and one carries three — and after
/// dedup every rule has exactly one DISTINCT stream selector.
#[test]
#[ignore = "reads a file outside this repo; run with --ignored"]
fn loki_regeln_yml_matches_the_2026_09_20_measurement() {
    let Ok(text) = std::fs::read_to_string(LOKI_REGELN) else {
        eprintln!("skip: {LOKI_REGELN} not present — no monitoring repo next to this checkout");
        return;
    };

    let rules =
        crosshair::loki::rules_from_yaml(&text).expect("loki-regeln.yml must parse as YAML");

    eprintln!("loki-regeln.yml: {} rules", rules.len());
    assert_eq!(
        rules.len(),
        16,
        "rule count drifted from the 2026-09-20 measurement"
    );

    for rule in &rules {
        let distinct = logql::stream_selectors(&rule.expr);
        assert_eq!(
            distinct.len(),
            1,
            "{} does not have exactly one distinct stream selector after dedup: {distinct:?}",
            rule.name
        );
    }
}
