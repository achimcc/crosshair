//! The one place that prints. Findings first, hints after, the summary last.
//!
//! `Origin::label()` names a rule by its NAME ALONE — exceptions in
//! `crosshair.toml` match a rule by name only, and `Origin::label()`'s own
//! test (Task 4, `a_rule_and_a_panel_label_themselves_differently`) pins that
//! the source is not in it. Two rules of the same name can live in Prometheus
//! and in Loki at once, and a report that only names them would make them
//! indistinguishable. So the SOURCE is printed here, alongside the label, by
//! matching on `Origin` directly — not inside `label()`.

use crate::run::Outcome;
use crate::selector::{Check, Origin, Verdict};

fn where_it_comes_from(o: &Origin) -> String {
    match o {
        Origin::Rule { source, rule } => format!("{source}  {rule}"),
        Origin::Panel { .. } => o.label(),
    }
}

/// One report line for a check — empty for `Live`, which the summary counts
/// but the listing does not spell out.
pub fn line(c: &Check) -> String {
    match (c.verdict, c.excepted) {
        (Verdict::Dead, false) => {
            format!(
                "  DEAD   {:<44} {}",
                where_it_comes_from(&c.origin),
                c.selector
            )
        }
        (Verdict::Dead, true) => {
            format!(
                "  (dead) {:<44} {}  — excepted",
                where_it_comes_from(&c.origin),
                c.selector
            )
        }
        (Verdict::Quiet, _) => {
            format!(
                "  quiet  {:<44} {}",
                where_it_comes_from(&c.origin),
                c.selector
            )
        }
        (Verdict::Live, _) => String::new(),
    }
}

pub fn print(o: &Outcome) {
    println!("\ncrosshair — does this rule point at anything real?\n");

    for c in &o.checks {
        let l = line(c);
        if !l.is_empty() {
            println!("{l}");
        }
    }
    for f in &o.findings {
        println!("  ERROR  {f}");
    }
    for n in &o.notes {
        println!("  note   {n}");
    }
    for t in &o.tool_failures {
        println!("  TOOL   {t}");
    }

    let live = o
        .checks
        .iter()
        .filter(|c| c.verdict == Verdict::Live)
        .count();
    let quiet = o
        .checks
        .iter()
        .filter(|c| c.verdict == Verdict::Quiet)
        .count();
    let dead = o
        .checks
        .iter()
        .filter(|c| c.verdict == Verdict::Dead && !c.excepted)
        .count();
    let excepted = o.checks.iter().filter(|c| c.excepted).count();
    println!(
        "\n  {live} live, {quiet} quiet, {dead} dead, {excepted} excepted, {} errors, {} notes\n",
        o.findings.len(),
        o.notes.len()
    );
    match o.exit_code() {
        0 => println!(
            "Every selector points at series that exist. `quiet` is a hint, not a failure.\n"
        ),
        1 => {
            println!("At least one selector points at nothing — that rule or panel cannot work.\n")
        }
        _ => println!("TOOL FAILURE: this run says NOTHING about the rules.\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::{Origin, Verdict};

    /// Exceptions in `crosshair.toml` match a rule by NAME ONLY —
    /// `Origin::label()` therefore cannot carry the source, and it does not
    /// (Task 4's own test pins that). The report still has to tell a
    /// Prometheus rule and a Loki rule of the same name apart, so the SOURCE
    /// is printed alongside the label here, not folded into it.
    #[test]
    fn a_loki_rule_shows_its_source_in_the_line() {
        let c = Check {
            origin: Origin::Rule {
                source: "loki".into(),
                rule: "X".into(),
            },
            selector: "sel".into(),
            verdict: Verdict::Dead,
            excepted: false,
        };
        let l = line(&c);
        assert!(l.contains("loki"), "line does not name the source: {l}");
        assert!(l.contains('X'), "line does not name the rule: {l}");
    }
}
