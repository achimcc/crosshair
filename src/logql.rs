//! Pulling the stream selectors out of a LogQL expression.
//!
//! WHY NOT A FULL PARSER: for this question only the `{…}` at the front of a
//! pipeline matters. The rest of the pipeline says how the lines are filtered,
//! not which stream they come from — and there is no LogQL parser crate that
//! would be worth the dependency for one brace scan.
//!
//! WHAT IT MUST KNOW ANYWAY: where a string begins. LogQL quotes line filters
//! with backticks, double or single quotes, and a regex quantifier such as
//! `{2,3}` inside one looks exactly like a selector to a naive scanner.

/// Every top-level `{…}` block, braces included, in source order, without
/// repeats.
pub fn stream_selectors(expr: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut start: Option<usize> = None;

    for (i, c) in expr.char_indices() {
        if let Some(q) = quote {
            // Backticks take no escapes — that is LogQL's raw string.
            if q != '`' && c == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if c == q && !escaped {
                quote = None;
            }
            escaped = false;
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '{' if start.is_none() => start = Some(i),
            '}' => {
                if let Some(s) = start.take() {
                    let text = expr[s..=i].to_string();
                    if !out.contains(&text) {
                        out.push(text);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_selector_comes_out_with_its_braces() {
        assert_eq!(
            stream_selectors(
                r#"sum(rate({gast="infra-01", unit="caddy.service"} | json | status="401" [5m]))"#
            ),
            vec![r#"{gast="infra-01", unit="caddy.service"}"#]
        );
    }

    /// `ErsteAnmeldungSeitDreissigTagen` names the same stream three times.
    #[test]
    fn repeats_collapse_to_one_question() {
        let e = r#"sum({gast="auth-01"} [15m]) unless sum({gast="auth-01"} [30d]) unless sum({gast="auth-01"} [24h])"#;
        assert_eq!(stream_selectors(e), vec![r#"{gast="auth-01"}"#]);
    }

    #[test]
    fn two_different_streams_are_two_questions() {
        let e = r#"count_over_time({gast="server"} [15m]) unless on() count_over_time({gast="vps"} [30m])"#;
        assert_eq!(
            stream_selectors(e),
            vec![r#"{gast="server"}"#, r#"{gast="vps"}"#]
        );
    }

    /// A REGEX QUANTIFIER IS NOT A SELECTOR. LogQL quotes its line filters with
    /// backticks, and `{2,3}` inside one is a repetition count. A scanner that
    /// counts braces without knowing where a string begins asks Loki about
    /// `{2,3}` and reports the rule as dead.
    #[test]
    fn braces_inside_a_line_filter_are_not_selectors() {
        let e = "count_over_time({job=\"x\"} |~ `err{2,3}` [5m])";
        assert_eq!(stream_selectors(e), vec![r#"{job="x"}"#]);
    }

    #[test]
    fn a_brace_inside_a_label_value_does_not_end_the_selector() {
        assert_eq!(
            stream_selectors(r#"{gast="a}b"} |= "x""#),
            vec![r#"{gast="a}b"}"#]
        );
    }

    /// Same rule as everywhere else in this repo: a search that can find
    /// nothing must say so, not return an empty success.
    #[test]
    fn an_expression_without_a_selector_yields_nothing() {
        assert!(stream_selectors("1 + 1").is_empty());
    }
}
