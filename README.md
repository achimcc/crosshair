# crosshair

Does this alerting rule or dashboard panel point at anything real?

An alerting rule whose selector matches no series is not red — it is
**silent**, and silent looks exactly like calm. Prometheus loads it,
evaluates it, gets an empty vector, and never fires. crosshair puts every
selector of every loaded rule and every dashboard panel target to the
running instance, over two lookback windows, and reports which ones point at
nothing.

## Why the existing tools cannot answer this

- `promtool test rules` proves a rule's *logic* against series it invents
  itself — it cannot see that the real series does not exist, because it
  never asked the real instance.
- `lokitool rules check` parses LogQL syntax. A selector that is
  syntactically fine and matches no stream passes it unchanged.
- A dashboard panel never turns red for a dead query. It turns **empty**,
  and an empty panel and a quiet one look identical in a screenshot.

None of the three asks the one question that matters here: does this
selector, run against the instance right now, return a series?

## Two windows, three verdicts

One lookback window cannot answer the question either. Measured on the
running installation on 2026-09-20, against `leakwatch`'s own metrics:

| lookback | `leakwatch_finding` | `leakwatch_run_timestamp` |
|---|---:|---:|
| 5 min | 0 series | 2 |
| 60 min | 0 series | 2 |
| 24 h | 18 | 2 |
| 7 days | 18 | 2 |

With a short window alone, a perfectly healthy rule — one that just has
nothing to report right now — looks dead. Without a window at all,
Prometheus falls back to its whole retention and becomes too forgiving: a
metric that died two weeks ago still looks alive today.

So every selector gets two questions, one long (default 7 days) and one
short (default 15 minutes), and one of three verdicts:

| long window | short window | verdict | meaning |
|---|---|---|---|
| empty | — | **dead** | nothing in the long window — the rule cannot fire. The series may never have existed, or may be older than the window |
| hit | empty | **quiet** | a hint, not a failure — normal for a counter that only moves on an event |
| hit | hit | **live** | active right now |

A `dead` verdict says exactly this much: the selector matched nothing over
the long window. Whether that is a wrong metric name, a wrong label value,
or an event that simply has not happened recently is the triage step that
follows, and crosshair does not decide it for you — the first real run found
a selector absent over seven days whose series turned out to exist, just
older (see below). The verdict itself stays right to report: a selector
that has matched nothing in seven days is still worth a red exit, whatever
the reason turns out to be.

This also spares a hand-written exception for every `absent()` rule in this
household's alert file: their metrics exist in normal operation too, or the
rule checking for their absence would be pointless. The distinction is
derived from the two windows, not maintained as a list.

## The positive control

A run that reports "0 dead selectors" and a run whose HTTP calls went
nowhere print the same thing unless something proves the difference. Before
touching any real selector, crosshair asks each source two of its own:

- one that must match (`up` on Prometheus, `{job="systemd-journal"}` on
  Loki),
- one that must not (a label value invented for this purpose).

The one that must match has to match in **both** windows — `up` on
Prometheus, the journal stream on Loki. Asked over the long window alone, an
instance that stopped ingesting yesterday still has seven days of it to
show; the control passed, every selector came back `quiet`, and `quiet`
changes no exit code — a deaf instance read as a calm week. Since 0.2.0 a
control that is empty in the short window is a tool failure.

If the first misses or the second hits, the run fails with exit 2 and says
why, instead of quietly reporting a clean bill of health for a source it
never actually reached.

## Exit status

| Code | Meaning |
|---|---|
| `0` | nothing dead, both controls on every source came back right |
| `1` | at least one dead selector, or an expression the instance refuses to evaluate |
| `2` | tool failure — a control failed, an API did not answer, an inventory was empty, an expression did not parse, an exception matched nothing any more, or the run checked no selector at all |

`quiet` never changes the exit code by itself. It is printed, not alarmed on.

Three of those exit-2 cases were added in 0.1.1, and they are all the same
kind of thing — a run that produced no verdict used to produce a clean bill
of health instead:

- **An empty inventory.** A Prometheus with no rule loaded, or a Grafana
  whose search returns no dashboard, is not a green run. It is an empty one,
  and it now says so. (An empty Loki rule file always did.)
- **A run that checked nothing.** If no source produced a single check and
  nothing failed, the run says nothing about the rules and exits 2 rather
  than printing "Every selector points at series that exist."
- **The Grafana source runs Prometheus' control too.** Its panel verdicts
  come from `/api/v1/series` against Prometheus, not from Grafana, so
  Grafana's own control does not cover them. It is skipped when the
  Prometheus source already ran it in the same run.

## Usage

```
USAGE:
    crosshair check [OPTIONS]

OPTIONS:
        --prometheus URL     default http://localhost:9090
        --loki URL           default http://localhost:3100
        --loki-rules FILE    the LogQL rules; the Ruler API is not enabled here
        --grafana URL        default http://127.0.0.1:3000
        --grafana-token-file PATH
                             a Grafana service-account token, role Viewer, sent
                             as `Authorization: Bearer`; the file holds the
                             token alone (a trailing newline is fine)
        --via-ssh TARGET     reach prometheus and loki through ssh + curl
        --source LIST        prometheus,loki,grafana (default: all three);
                             an unknown name is an error, never a no-op
        --long DURATION      long window, default 7d
        --short DURATION     short window, default 15m
    -c, --config FILE        exceptions, each needs a reason
    -h, --help
    -V, --version
```

`--source` takes only those three names, and since 0.1.1 an unknown one is
refused by name. Before that, `--source promethues` ran not a single check,
produced an empty result and exited 0 under the line "Every selector points
at series that exist." — this tool's own failure mode, one level up. A
narrowed run also skips the exception file's staleness check and says so:
that check asks the whole file, and an entry scoped to a source this run
never visited would look unused without being it.

Prometheus and Loki commonly listen on an address the workstation running
crosshair cannot reach directly; `--via-ssh` wraps the same `curl` calls in
an `ssh`. Grafana is usually reached through an ordinary local port-forward
instead:

```console
$ ssh -f -N -L 3000:10.0.20.12:3000 server   # Grafana's own tunnel
$ crosshair check \
    --prometheus http://10.0.20.12:9090 \
    --loki       http://10.0.20.12:3100 \
    --loki-rules loki-regeln.yml \
    --via-ssh    server \
    --grafana    http://127.0.0.1:3000 \
    --grafana-token-file "$XDG_RUNTIME_DIR/grafana-crosshair.token" \
    --config     crosshair.toml
```

### Signing in to Grafana

crosshair only reads from Grafana — the dashboard search, the dashboards
themselves and `/api/ds/query` — so it signs in with a **service-account
token with the role Viewer** and nothing more. Create one under
*Administration → Service accounts*, put the token alone into a file (one
trailing newline is fine, anything else is refused), and pass the file with
`--grafana-token-file`. Without the option crosshair asks Grafana
anonymously.

The token goes out as `Authorization: Bearer …`, to Grafana and to nothing
else. It never appears in argv: crosshair writes the header into a file of
its own, mode 0600, hands curl only its path (`-H @file`) and removes it when
the run ends. No error message quotes the token.

Until 0.1.x crosshair logged in with the Grafana **admin** password through
`/login` (`--grafana-password-file`) and kept a session cookie, renewing it
whenever Grafana rotated the session — the one credential that can change
every dashboard, held by a tool that changes none. 0.2.0 removed that path
and the option with it; passing `--grafana-password-file` is now an error.

## The exception file — `crosshair.toml`

Same pattern as `unit-lint.toml` and `leakwatch.toml`: every entry names a
scope (a `rule` by name, or a `dashboard` optionally narrowed to one
`panel`), optionally one `selector` inside that scope, and a mandatory
`reason`. An entry without a reason fails to parse; so does one that names
both a `rule` and a `dashboard`, or a `rule` and a `panel` — `panel` narrows
a `dashboard` and nothing else, and next to a `rule` it used to be accepted
and then ignored, quietly widening the entry to every dead selector of that
rule. `selector` is compared as an exact string: there is no prefix, glob or
regular-expression matching, so one entry excepts one selector. An entry that matches
nothing any more — the exception outlived what it excepted — turns the run
red instead of aging silently:

```toml
[[exception]]
rule = "TifTrefferImHaus"
selector = 'blocky_response_total{reason="BLOCKED (threat)"}'
reason = "the block group is live (2.6M denylist entries); nobody in seven days has asked for a threat domain"
```

### `optional = true`

It exists from the first version, for a reason already paid for by a
sibling tool: `leakwatch` stood red three hours after its own rollout
because a legitimate, correct exception matched nothing in that particular
window — it had 18 hits at noon and none three hours later. Frequency is no
protection when what you are looking at is a burst, not a rate. A selector
that only appears while something specific is happening needs
`optional = true` (`rule = "…"`, plus the flag, plus a reason) from day one,
not after the first false alarm — it exempts that one entry from the
staleness check and nothing else. Leaving it out, the default, keeps the
check on.

## The Loki caveat

Named rather than hidden: this installation's Ruler API answers 404 on
`/loki/api/v1/rules`, `/prometheus/api/v1/rules`, and `/api/prom/rules`
alike. So crosshair reads Loki's alerting rules from the same YAML file the
deploy ships, not from what Loki actually loaded — the one place it departs
from "ask the running instance, not the source file" that governs
everywhere else. A rule checked here may, in principle, be one Loki never
loaded at all (a YAML error, a rule the Ruler rejected). `lokitool rules
check` covers exactly that other half; crosshair does not replace it for
Loki the way it replaces `promtool`'s and Grafana's rule inventories.

## What it deliberately does not do

- **No daemon.** This is a command for the moment a rule or a panel is
  written, not a permanent sensor — a metric about alerting rules would hang
  off the very chain it is meant to check.
- **No opinion on the threshold.** Whether `> 0.8` is the right number is
  not a question this tool can answer; it only asks whether anything is
  being measured at all.
- **No replacement for `promtool` or `lokitool`.** Syntax checks and
  evaluation against invented input stay there. crosshair answers the one
  question neither of them can: does the expression point at the world?

## What the first run found

The most convincing paragraph in this file is a measurement, not a claim.
On 2026-09-20, against the live installation, crosshair found a Grafana
panel titled "dropped by Loki" whose expression was

```
sum(rate(loki_discarded_samples_total[5m])) or vector(0)
```

The `or vector(0)` is well-intentioned — it turns "no data" into a
reassuring flat line instead of a gap. It also turns "the metric has not
existed for over a week" into the same flat line. crosshair's selector-level
check found `loki_discarded_samples_total` present over 14, 30 and 90 days
but absent over 1 and 7 — Loki last discarded something more than a week
before the run. The predecessor tool, which only counts whether a panel's
query returns *any* data point, counted this same panel as healthy: `or
vector(0)` guarantees exactly one data point, always. A panel can look green
while the number behind it has been gone for a week, and nothing about the
panel itself says so.

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
