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

/// The threshold is `900`, matching `GastSpeicherSensorVeraltet` at
/// `hosts/server/gaeste/obs-regeln.yml:213` exactly (verified 2026-09-20,
/// review round 2 — an earlier draft carried `1800`, a value that belongs to
/// a different rule; the point of this file is that the frozen text is the
/// shipped text, so it had to be corrected against the source, not guessed).
#[test]
fn the_textfile_freshness_shape_with_its_escaped_regex() {
    let src = r#"time() - node_textfile_mtime_seconds{file=~".*/gast-speicher\\.prom"} > 900"#;
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
// missing; run them explicitly with
// `cargo test --test rules -- --ignored --nocapture`.
//
// THE `--nocapture` IS NOT OPTIONAL, AND THIS IS THE TRAP TO REMEMBER:
// libtest swallows the captured stdout/stderr of a PASSING test. A skip
// path that returns `Ok` after `eprintln!`-ing a note is indistinguishable,
// without `--nocapture`, from a run that read the file and verified the
// measurement — `cargo test --test rules -- --ignored` alone prints
// nothing but `ok` either way. That is exactly the failure mode this whole
// tool exists to catch elsewhere: a green result that means "I did not
// look". Found in review round 2 (2026-09-20); fixed by requiring
// `--nocapture` in every place this file documents the invocation, wording
// the skip note as `SKIPPED: ...` so it cannot be mistaken for a pass, and
// adding `CROSSHAIR_RULES_REQUIRED=1` below to turn the skip into a hard
// failure on a machine where the file is known to exist.
//
// THE DEFAULT DIRECTORY IS THE MAIN CHECKOUT, NOT A WORKTREE — found in
// review round 3 (2026-09-20). An earlier version pointed at
// `~/Projects/homeserver/.claude/worktrees/leakwatch/...`, a SCRATCH git
// worktree made for one piece of work. That worktree is deleted once its
// branch is done; on that day both tests below would start skipping —
// quietly, forever, on the very machine where they are meant to mean
// something. A loud skip that never triggers because the path never exists
// again is the same failure as a silent one, just delayed. The default is
// therefore `~/Projects/homeserver/hosts/server/gaeste`, the long-lived main
// checkout. It is still just a guess about the reader's machine — a
// hard-coded home directory has no business being load-bearing in a public
// repository — so `CROSSHAIR_RULES_DIR` overrides it: set it to point at
// any checkout's `hosts/server/gaeste` and both tests read from there.

/// The directory holding `obs-regeln.yml` and `loki-regeln.yml`: the value
/// of `CROSSHAIR_RULES_DIR` if set, otherwise the main homeserver checkout.
fn rules_dir() -> String {
    std::env::var("CROSSHAIR_RULES_DIR")
        .unwrap_or_else(|_| "/home/achim/Projects/homeserver/hosts/server/gaeste".to_string())
}

fn obs_regeln_path() -> String {
    format!("{}/obs-regeln.yml", rules_dir())
}

fn loki_regeln_path() -> String {
    format!("{}/loki-regeln.yml", rules_dir())
}

/// Reads `path`, or explains why the caller must return early — loudly.
///
/// With `CROSSHAIR_RULES_REQUIRED` set, a missing file is a **failure**, not
/// a skip: use that on a machine where the monitoring repo is known to sit
/// next door (this checkout, CI for this pairing, ...) so the measurement
/// cannot go silently unverified. Without it, a bare `cargo test` from
/// anywhere else stays green, but only when run with `--nocapture` does the
/// note actually reach the screen — see the module comment above.
fn read_rule_file_or_skip(path: &str) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) => {
            let note = format!(
                "SKIPPED: {path} not found ({e}) — this machine has no monitoring \
                 repo next door, so the 2026-09-20 measurement was NOT verified."
            );
            if std::env::var_os("CROSSHAIR_RULES_REQUIRED").is_some() {
                panic!("{note} CROSSHAIR_RULES_REQUIRED is set — treating this as a failure.");
            }
            eprintln!("{note}");
            None
        }
    }
}

/// This one runs by default (not `#[ignore]`d, no env var touched) so the
/// skip half of `read_rule_file_or_skip` is exercised on every plain
/// `cargo test`, on a machine with or without the monitoring repo. It does
/// not assert on captured output — libtest's own capturing is the exact
/// thing Finding 1 was about — only on the `None` contract.
#[test]
fn a_missing_rule_file_skips_without_the_required_env_var() {
    assert!(read_rule_file_or_skip("/no/such/path/crosshair-test-probe.yml").is_none());
}

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
#[ignore = "reads a file outside this repo; run with --ignored --nocapture"]
fn obs_regeln_yml_matches_the_2026_09_20_measurement() {
    let Some(text) = read_rule_file_or_skip(&obs_regeln_path()) else {
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
#[ignore = "reads a file outside this repo; run with --ignored --nocapture"]
fn loki_regeln_yml_matches_the_2026_09_20_measurement() {
    let Some(text) = read_rule_file_or_skip(&loki_regeln_path()) else {
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
