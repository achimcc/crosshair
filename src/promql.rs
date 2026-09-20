//! Pulling every vector selector out of a PromQL expression.
//!
//! WHY A PARSER AND NOT A REGEX: the bash version this replaces needed a
//! blocklist of SIXTY PromQL function names to tell a function from a metric.
//! A blocklist of function names is the sign that a parser is missing.

use promql_parser::parser::{self, Expr, VectorSelector};
use promql_parser::util::{ExprVisitor, walk_expr};

/// Every vector selector of `expr`, in source order, without repeats.
pub fn selectors(expr: &str) -> Result<Vec<String>, String> {
    let ast = parser::parse(expr)?;
    let mut c = Collector::default();
    walk_expr(&mut c, &ast).expect("the collector cannot fail");
    Ok(c.out)
}

#[derive(Default)]
struct Collector {
    out: Vec<String>,
}

impl ExprVisitor for Collector {
    type Error = std::convert::Infallible;

    fn pre_visit(&mut self, e: &Expr) -> Result<bool, Self::Error> {
        // A MATRIX SELECTOR IS A LEAF. `walk_expr` recurses into Aggregate,
        // Unary, Binary, Paren, Subquery, Call and Extension — and treats
        // `Expr::MatrixSelector` as terminal, although it carries a
        // `VectorSelector` inside. Unwrapping it here is the difference
        // between finding 101 selectors in this repo and finding a handful.
        let vs = match e {
            Expr::VectorSelector(vs) => vs,
            Expr::MatrixSelector(ms) => &ms.vs,
            _ => return Ok(true),
        };
        let text = render(vs);
        if !self.out.contains(&text) {
            self.out.push(text);
        }
        Ok(true)
    }
}

/// The selector the way `/api/v1/series` wants it: name and matchers, nothing
/// else. `@` and `offset` describe WHEN the expression looks, not WHICH series
/// it means, and the series endpoint rejects them.
fn render(vs: &VectorSelector) -> String {
    let mut bare = vs.clone();
    bare.at = None;
    bare.offset = None;
    bare.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A matrix selector is a LEAF for `walk_expr` — it never descends into the
    /// vector selector inside it. Most alerting rules in this house are
    /// `rate(foo[5m])`, so a visitor that only handles `Expr::VectorSelector`
    /// finds nothing in the majority of them and reports a healthy repo.
    #[test]
    fn a_range_selector_is_not_skipped() {
        assert_eq!(
            selectors("increase(insist_raise_failures_total[30m]) > 0").unwrap(),
            vec!["insist_raise_failures_total"]
        );
    }

    /// 2026-09-06: `radarr_movie_filesize_total + sonarr_series_filesize_bytes`
    /// was not wrong, it was EMPTY — and one of the two summands was enough.
    #[test]
    fn both_sides_of_a_binary_expression_are_collected() {
        assert_eq!(
            selectors("radarr_movie_filesize_total + sonarr_series_filesize_bytes").unwrap(),
            vec![
                "radarr_movie_filesize_total",
                "sonarr_series_filesize_bytes"
            ]
        );
    }

    #[test]
    fn labels_travel_with_the_name() {
        assert_eq!(
            selectors(r#"up{job="insist"} == 0"#).unwrap(),
            vec![r#"up{job="insist"}"#]
        );
    }

    /// `absent()` is not a special case: the series must exist either way, or
    /// the rule says nothing about its absence.
    #[test]
    fn a_selector_inside_absent_is_collected_like_any_other() {
        assert_eq!(
            selectors(r#"absent(up{job="insist"})"#).unwrap(),
            vec![r#"up{job="insist"}"#]
        );
    }

    /// The same selector twice in one expression is one question.
    #[test]
    fn duplicates_within_one_expression_collapse() {
        assert_eq!(
            selectors(r#"up{job="insist"} == 0 or absent(up{job="insist"})"#).unwrap(),
            vec![r#"up{job="insist"}"#]
        );
    }

    /// `@` and `offset` belong to the expression, not to the series — and
    /// /api/v1/series refuses them. Three rules in obs-regeln.yml carry one.
    #[test]
    fn offset_and_at_are_dropped() {
        assert_eq!(
            selectors("sum(node_boot_time_seconds offset 1h)").unwrap(),
            vec!["node_boot_time_seconds"]
        );
    }

    /// A regex matcher must survive the round trip through our rendering,
    /// backslashes and all — otherwise we ask about a different series than
    /// the rule does.
    #[test]
    fn a_regex_matcher_renders_back_to_the_same_ast() {
        let src = r#"node_textfile_mtime_seconds{file=~".*/gast-speicher\\.prom"}"#;
        let rendered = &selectors(src).unwrap()[0];
        assert_eq!(
            promql_parser::parser::parse(rendered).unwrap(),
            promql_parser::parser::parse(src).unwrap()
        );
    }

    /// The deadman. An expression without a selector is not a finding — it is
    /// a case to be NAMED, like the skipped targets of dashboard-pruefen.
    #[test]
    fn an_expression_without_a_selector_yields_nothing() {
        assert!(selectors("vector(1)").unwrap().is_empty());
    }

    #[test]
    fn an_unparsable_expression_is_an_error_not_an_empty_list() {
        assert!(selectors("sum(((").is_err());
    }
}
