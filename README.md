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
| empty | — | **dead** | the series has never existed; the rule cannot fire |
| hit | empty | **quiet** | a hint, not a failure — normal for a counter that only moves on an event |
| hit | hit | **live** | active right now |

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

If the first misses or the second hits, the run fails with exit 2 and says
why, instead of quietly reporting a clean bill of health for a source it
never actually reached.

## Exit status

| Code | Meaning |
|---|---|
| `0` | nothing dead, both controls on every source came back right |
| `1` | at least one dead selector, or an expression the instance refuses to evaluate |
| `2` | tool failure — a control failed, an API did not answer, an expression did not parse, or an exception matched nothing any more |

`quiet` never changes the exit code by itself. It is printed, not alarmed on.

## Usage

```
USAGE:
    crosshair check [OPTIONS]

OPTIONS:
        --prometheus URL     default http://localhost:9090
        --loki URL           default http://localhost:3100
        --loki-rules FILE    the LogQL rules; the Ruler API is not enabled here
        --grafana URL        default http://127.0.0.1:3000
        --grafana-password-file PATH
        --via-ssh TARGET     reach prometheus and loki through ssh + curl
        --source LIST        prometheus,loki,grafana (default: all three)
        --long DURATION      long window, default 7d
        --short DURATION     short window, default 15m
    -c, --config FILE        exceptions, each needs a reason
    -h, --help
    -V, --version
```

Prometheus and Loki commonly listen on an address the workstation running
crosshair cannot reach directly; `--via-ssh` wraps the same `curl` calls in
an `ssh`. Grafana is usually reached through an ordinary local port-forward
instead, since it also needs a login and a cookie jar for the session:

```console
$ ssh -f -N -L 3000:10.0.20.12:3000 server   # Grafana's own tunnel
$ crosshair check \
    --prometheus http://10.0.20.12:9090 \
    --loki       http://10.0.20.12:3100 \
    --loki-rules loki-regeln.yml \
    --via-ssh    server \
    --grafana    http://127.0.0.1:3000 \
    --grafana-password-file /run/secrets/grafana-admin-password \
    --config     crosshair.toml
```

## The exception file — `crosshair.toml`

Same pattern as `unit-lint.toml` and `leakwatch.toml`: every entry names a
scope (a `rule` by name, or a `dashboard` optionally narrowed to one
`panel`), optionally one `selector` inside that scope, and a mandatory
`reason`. An entry without a reason fails to parse. An entry that matches
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
