//! The judgement, and the two windows it needs.
//!
//! ONE LOOKBACK WINDOW CANNOT ANSWER THE QUESTION, and that is measured, not
//! assumed. On 2026-09-20 on the running installation:
//!
//! | lookback | leakwatch_finding | leakwatch_run_timestamp |
//! |----------|-------------------|-------------------------|
//! | 5 min    | 0 series          | 2                       |
//! | 60 min   | 0 series          | 2                       |
//! | 24 h     | 18                | 2                       |
//! | 7 days   | 18                | 2                       |
//!
//! With a short window the healthy rule looks dead. WITHOUT `start`/`end`
//! Prometheus takes the whole retention and is too forgiving: a metric that
//! died two weeks ago still looks alive.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Series in both windows.
    Live,
    /// Series in the long window only — quiet right now. A HINT, never a
    /// failure: an empty health table is the normal state of a healthy system.
    Quiet,
    /// Nothing in the long window. The rule cannot fire.
    Dead,
}

/// The whole distinction, DERIVED and not maintained by hand. It is what
/// spares the tool an exception for every `absent()` rule: their metrics exist
/// in normal operation too, or the rule would be pointless.
pub fn judge(long_hits: usize, short_hits: usize) -> Verdict {
    if long_hits == 0 {
        Verdict::Dead
    } else if short_hits == 0 {
        Verdict::Quiet
    } else {
        Verdict::Live
    }
}

#[derive(Debug, Clone)]
pub enum Origin {
    Rule {
        source: String,
        rule: String,
    },
    Panel {
        dashboard: String,
        panel: String,
        refid: String,
    },
}

impl Origin {
    pub fn label(&self) -> String {
        match self {
            Origin::Rule { rule, .. } => rule.clone(),
            Origin::Panel {
                dashboard,
                panel,
                refid,
            } => {
                format!("{dashboard} \"{panel}\" [{refid}]")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub origin: Origin,
    pub selector: String,
    pub verdict: Verdict,
    /// Set by `config.rs` when an exception covers this dead selector.
    pub excepted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Measured on the running installation on 2026-09-20:
    /// `leakwatch_finding` has 0 series over 5 and over 60 minutes and 18 over
    /// 24 hours. With one short window the healthy rule looks dead.
    #[test]
    fn empty_in_the_short_window_but_alive_in_the_long_one_is_quiet() {
        assert_eq!(judge(18, 0), Verdict::Quiet);
    }

    /// Nothing over seven days: the series has never been there, the rule
    /// cannot fire. This is the finding the tool exists for.
    #[test]
    fn empty_in_the_long_window_is_dead() {
        assert_eq!(judge(0, 0), Verdict::Dead);
    }

    #[test]
    fn present_in_both_windows_is_live() {
        assert_eq!(judge(18, 2), Verdict::Live);
    }

    /// Both windows have hits: the series is active and healthy. Live verdict
    /// regardless of which window carries the data.
    #[test]
    fn both_windows_with_one_hit_each_is_live() {
        assert_eq!(judge(1, 1), Verdict::Live);
    }

    /// Nothing over seven days but something in the last fifteen minutes is
    /// arithmetically impossible — the short window lies INSIDE the long one.
    /// The branch is pinned anyway: the verdict must follow the long window
    /// alone, not the shape of the data that happens to arrive.
    #[test]
    fn nothing_in_the_long_window_stays_dead_even_if_the_short_one_has_hits() {
        assert_eq!(judge(0, 5), Verdict::Dead);
    }

    #[test]
    fn a_rule_and_a_panel_label_themselves_differently() {
        let r = Origin::Rule {
            source: "prometheus".into(),
            rule: "InsistSendetNicht".into(),
        };
        assert_eq!(r.label(), "InsistSendetNicht");
        let p = Origin::Panel {
            dashboard: "Services/arr-library.json".into(),
            panel: "Library size".into(),
            refid: "A".into(),
        };
        assert_eq!(p.label(), "Services/arr-library.json \"Library size\" [A]");
    }
}
