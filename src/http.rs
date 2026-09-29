//! The way to an HTTP endpoint — a spawned `curl`, optionally through `ssh`.
//!
//! NO HTTP CRATE, same choice as leakwatch: Prometheus, Loki and Grafana here
//! all listen on internal addresses a workstation cannot reach, so the answer
//! comes over `ssh … |` anyway. A trait in front of it keeps every adapter
//! testable against recorded answers.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub trait Http {
    fn get(&self, url: &str) -> Result<Value>;
    /// `body` goes to curl's STDIN, never into argv — argv is world-readable
    /// in /proc, and a body is the kind of thing that one day carries a secret.
    fn post(&self, url: &str, body: &str) -> Result<Value>;
}

/// Percent-encode everything but the unreserved set.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct Curl {
    pub via_ssh: Option<String>,
    /// A file of extra request headers, handed to curl as `-H @<path>`.
    ///
    /// THIS IS HOW THE GRAFANA TOKEN TRAVELS, and the only way that keeps it
    /// out of argv: `-H "Authorization: Bearer …"` or `--oauth2-bearer …`
    /// would put it in /proc/<pid>/cmdline for every local user to read.
    /// argv carries the PATH; the file is created 0600 by `main`.
    pub header_file: Option<PathBuf>,
}

/// Single-quote one argument for a remote `sh`. Everything inside single
/// quotes is literal; an embedded quote is closed, escaped and reopened.
///
/// THE URL IS ALREADY PERCENT-ENCODED when it gets here, so it cannot carry
/// a quote, a backtick, a space or a `$` — but a header-file path can, and the
/// ssh route hands the whole line to a shell.
fn sh_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

impl Curl {
    pub fn command(&self, url: &str) -> Vec<String> {
        self.command_with(url, &[])
    }

    /// The general form: `extra` are curl arguments that belong BEFORE the
    /// URL. They must go through the same wrapping as the rest — appending
    /// them after `command()` has already joined the line for `ssh` hands
    /// them to the remote shell unquoted, where `Content-Type: application/json`
    /// word-splits into two arguments.
    fn command_with(&self, url: &str, extra: &[&str]) -> Vec<String> {
        let mut curl: Vec<String> = vec![
            "curl".into(),
            "-sS".into(),
            "--fail".into(),
            "--max-time".into(),
            "120".into(),
        ];
        if let Some(headers) = &self.header_file {
            curl.push("-H".into());
            curl.push(format!("@{}", headers.display()));
        }
        curl.extend(extra.iter().map(|a| a.to_string()));
        curl.push(url.to_string());
        match &self.via_ssh {
            // Local: no shell in between, so the argument list goes as it is.
            None => curl,
            Some(target) => vec![
                "ssh".into(),
                "-o".into(),
                "IdentitiesOnly=yes".into(),
                target.clone(),
                curl.iter()
                    .map(|a| sh_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            ],
        }
    }

    fn run(&self, mut argv: Vec<String>, body: Option<&str>) -> Result<Value> {
        // The whole body is written before `wait_with_output()` starts draining
        // stdout — fine only because every body here is a small JSON blob; a
        // large one and a curl that answers before reading all of stdin would
        // deadlock on curl's stdout pipe filling up while we block on write.
        let prog = argv.remove(0);
        let mut child = Command::new(&prog)
            .args(&argv)
            .stdin(if body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning {prog}"))?;
        if let Some(b) = body {
            child.stdin.take().unwrap().write_all(b.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "{prog} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        serde_json::from_slice(&out.stdout).with_context(|| {
            format!(
                "the answer is not JSON: {}",
                String::from_utf8_lossy(&out.stdout)
                    .chars()
                    .take(160)
                    .collect::<String>()
            )
        })
    }
}

impl Http for Curl {
    fn get(&self, url: &str) -> Result<Value> {
        self.run(self.command(url), None)
    }
    fn post(&self, url: &str, body: &str) -> Result<Value> {
        let argv = self.command_with(
            url,
            &[
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
            ],
        );
        self.run(argv, Some(body))
    }
}

/// Recorded answers, matched by a substring of the URL. An unexpected URL is
/// an ERROR and not an empty answer — a test that silently gets `{}` proves
/// nothing.
pub struct Canned {
    answers: Vec<(String, Value)>,
}

impl Canned {
    pub fn new(pairs: Vec<(&str, &str)>) -> Self {
        Canned {
            answers: pairs
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        serde_json::from_str(v).expect("fixture is JSON"),
                    )
                })
                .collect(),
        }
    }
    fn find(&self, url: &str) -> Result<Value> {
        self.answers
            .iter()
            .find(|(k, _)| url.contains(k.as_str()))
            .map(|(_, v)| v.clone())
            .with_context(|| format!("no recorded answer for {url}"))
    }
}

impl Http for Canned {
    fn get(&self, url: &str) -> Result<Value> {
        self.find(url)
    }
    fn post(&self, url: &str, _body: &str) -> Result<Value> {
        self.find(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EVERYTHING GOES INTO THE URL PERCENT-ENCODED, and that is not tidiness:
    /// over ssh the command is one string for a remote shell. On 2026-09-12
    /// `loki-regeln-stellen.sh` sent an expression with backticks through a
    /// double-quoted ssh command, the remote shell EXECUTED them, Loki
    /// answered `success` with zero series, and the tool declared all ten
    /// rules of the repo dead. An encoded URL contains no quote, no backtick
    /// and no space, so single quotes around it are enough.
    #[test]
    fn encoding_leaves_nothing_a_shell_could_read() {
        let e = percent_encode(r#"up{job="insist"}"#);
        assert_eq!(e, "up%7Bjob%3D%22insist%22%7D");
        assert!(!e.contains(['"', '\'', '`', ' ', '$']));
    }

    #[test]
    fn unreserved_characters_survive_unchanged() {
        assert_eq!(percent_encode("abc_XYZ-09.~"), "abc_XYZ-09.~");
    }

    #[test]
    fn a_backtick_is_encoded_too() {
        assert!(!percent_encode("err{2,3}`x`").contains('`'));
    }

    #[test]
    fn the_local_command_is_curl_and_the_remote_one_is_ssh_wrapped() {
        let local = Curl {
            via_ssh: None,
            header_file: None,
        };
        assert_eq!(local.command("http://x/y")[0], "curl");
        let remote = Curl {
            via_ssh: Some("server".into()),
            header_file: None,
        };
        let c = remote.command("http://x/y");
        assert_eq!(c[0], "ssh");
        assert!(c.last().unwrap().contains("'http://x/y'"));
    }

    /// A POST over ssh must arrive as ONE shell line with every argument
    /// quoted — including the header, whose space would otherwise split it
    /// into two arguments on the far side.
    #[test]
    fn a_post_over_ssh_keeps_its_header_in_one_piece() {
        let c = Curl {
            via_ssh: Some("server".into()),
            header_file: None,
        };
        let argv = c.command_with(
            "http://x/y",
            &[
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
            ],
        );
        assert_eq!(
            argv.len(),
            5,
            "everything after the target must be one argument: {argv:?}"
        );
        let line = argv.last().unwrap();
        assert!(
            line.contains(r"'Content-Type: application/json'"),
            "header not quoted: {line}"
        );
        assert!(
            line.contains("'--data-binary' '@-'"),
            "body flag not quoted: {line}"
        );
    }

    /// A path with a space must survive the trip to the remote shell as ONE
    /// argument. The URL cannot carry one (it is percent-encoded before it
    /// gets here), but a header-file path can.
    #[test]
    fn a_path_with_a_space_stays_one_argument_for_the_remote_shell() {
        let c = Curl {
            via_ssh: Some("server".into()),
            header_file: Some("/tmp/my headers".into()),
        };
        let line = c.command("http://x/y").last().unwrap().clone();
        assert!(
            line.contains(r"'@/tmp/my headers'"),
            "header file not quoted: {line}"
        );
    }

    /// THE TOKEN IS NOT IN ARGV, ONLY ITS PATH. The header file is handed
    /// over as `-H @<path>`, which curl reads itself; nothing on the command
    /// line names the scheme or the credential.
    #[test]
    fn the_header_file_goes_in_by_path_and_nothing_else_does() {
        let c = Curl {
            via_ssh: None,
            header_file: Some("/tmp/h".into()),
        };
        let argv = c.command("http://x/y");
        let at = argv.iter().position(|a| a == "@/tmp/h").expect("no @path");
        assert_eq!(argv[at - 1], "-H");
        assert!(
            argv.iter()
                .all(|a| !a.contains("Bearer") && !a.contains("Authorization")),
            "{argv:?}"
        );
    }

    /// And locally the argument list must stay a plain argument list — no
    /// quotes to strip, because none were added.
    #[test]
    fn the_local_argument_list_carries_no_shell_quotes() {
        let c = Curl {
            via_ssh: None,
            header_file: Some("/tmp/h".into()),
        };
        assert!(c.command("http://x/y").iter().all(|a| !a.contains('\'')));
    }

    /// `-S` next to `-s`: `-s` alone silences the REASON along with the
    /// progress meter. leakwatch paid a deploy cycle for that on 2026-09-20 —
    /// a sensor aimed at a Loki that was not there reported "reading a line".
    #[test]
    fn curl_keeps_its_reason() {
        let c = Curl {
            via_ssh: None,
            header_file: None,
        }
        .command("http://x/y");
        assert!(c.contains(&"-sS".to_string()));
        assert!(c.contains(&"--fail".to_string()));
    }

    #[test]
    fn canned_answers_by_url_substring() {
        let h = Canned::new(vec![(
            "api/v1/series",
            r#"{"status":"success","data":[{}]}"#,
        )]);
        assert_eq!(
            h.get("http://x/api/v1/series?match[]=up").unwrap()["status"],
            "success"
        );
        assert!(
            h.get("http://x/unknown").is_err(),
            "an unexpected URL must fail loudly"
        );
    }
}
