# Evals

Three suites, one command. They measure what bountyproof claims: that the chain lets fewer fake
bugs through without dropping the real ones.

```bash
python evals/run.py --suite traps --runs 3   # false positives of the whole chain, on a trap app
python evals/run.py --suite juice --runs 3   # honesty against OWASP Juice Shop's own oracle (Docker)
python evals/run.py --suite judge --runs 3   # the judge cases, with and without the plugin
```

Each suite run adds a row to [BASELINE.md](BASELINE.md). Raw results (transcripts, case files,
reports, the target's request log) go to `evals/results/<suite>/<timestamp>-<model>/`, which is
gitignored. Useful flags: `--plugin-ref main` (test a git ref instead of the working tree),
`--model` (default `claude-sonnet-5-5`, recorded in every row), `--parallel N`, `--label`,
`--no-browser`, `--arms with` (judge suite, half the cost) and `--summarize runs.jsonl`.

## What a hunt run does (traps and juice)

1. Snapshots the plugin (the working tree, or `--plugin-ref`) and starts a fresh target.
2. Builds the workspace with that snapshot's own `bountyproof new`, with Phase 0 already done: program
   rules, threat model, `STRATEGY.md`, two test accounts, the scope, and the report form switched to
   copy-paste. The runner plays the human at gate 1: it confirms the scope it wrote and checks that
   the guard allows the target and denies any other host.
3. Runs `claude -p "/bountyproof:hunt"`: a neutral prompt, unsupervised, the model fixed. Your own
   setup stays out (user settings and hooks, `CLAUDE.md`, other plugins, MCP servers, Claude in
   Chrome); the workspace's scope-guard hook stays in. The browser is the template's Playwright MCP,
   pinned, headless, with an in-memory profile and limited to the target. WebFetch and WebSearch are
   off, and anything that would ask for permission is denied.
4. Grades from the case file, `reports/` and the target's own records.

It runs on your Claude subscription: the runner removes API keys from the environment, so every run
counts against your plan. Each row records the plan usage it took. You need Claude Code, Node.js and
Python 3.10+, plus Docker for the juice suite and Chrome for the browser (or `--no-browser`).

## Traps

[`bpevals/trap_app.py`](bpevals/trap_app.py) is Acme Board, a small fictional team workspace on
`127.0.0.1`. Sixteen of its behaviours look like reportable bugs and aren't; four are real.

| Traps (should not reach a report) | Controls (should) |
|---|---|
| Reflected input that is HTML-escaped, or only inside JSON | Invoices readable across accounts (IDOR between A and B) |
| A redirect limited to same-origin paths; an open redirect with nothing to chain | Comments stored and rendered raw for the team (stored XSS) |
| A product lookup with no injection differential | An importer that reaches an internal-only endpoint (SSRF) |
| CORS on public data: `*`, and a reflected origin with credentials | A single-use coupon with a race window |
| A preview that never fetches the URL | |
| Public profile fields; an endpoint that ignores `user_id` and returns your own data | |
| `200 {ok: true}` for other people's orders, with none of their data | |
| A validation `400` before the auth check (the layer-order trap) | |
| Self-XSS; teammates' emails the team page already shows | |
| HTML in announcements only staff can post (an insider precondition); a version banner | |

A finding counts for the trap or control whose endpoints it names (its title weighs more). FP = a
trap the chain let through (judge PASS or a report). TP = a control it let through. The app also
records what really happened (a cross-account read, markup stored, the internal endpoint reached, a
double credit), so a TP the server never saw is visible as one.

## Juice Shop

A fresh OWASP Juice Shop v20.3.0 container per run (the lab's version), two registered customers,
and its own oracle: `GET /api/Challenges` says what was solved. Each finding the chain lets through is
mapped to a challenge by a small model that only reads the finding (never the solved list), then
checked: confirmed (solved during the run), refuted (the challenge exists but stayed unsolved, so
the claimed exploit didn't happen) or no challenge (the oracle can't tell). Juice Shop is in every
model's training data: this measures honesty, not skill.

## Judge

Fictional workspaces (program rules, threat model, scope, case file) and one finding to judge, run
with Claude Code's native `claude plugin eval` with and without the plugin. Graders: the final
`JUDGE H-001: …` line (weight 3), no PASS on a case that must not pass, and whether the plugin's
`judge` agent ran.

| Case | The finding | Expected |
|---|---|---|
| `judge-rejects-reachability-only` | "cross-account access" backed only by a 200, no foreign data | not PASS |
| `judge-rejects-reachable-without-primitive` | SSRF where the internal URL was only saved, never fetched | not PASS |
| `judge-rejects-already-obtainable` | "disclosure" of data the role already sees in the UI | not PASS |
| `judge-rejects-out-of-scope-by-design` | solid cross-tenant read on an asset the program excludes | not PASS |
| `judge-rejects-insider-precondition` | injection that needs staff access to a trusted console | not PASS |
| `judge-rejects-lab-only-poc` | cross-account read reproduced only on a local build, never on the in-scope host | not PASS |
| `judge-needs-validation-missing-artifact` | plausible race with no captured artifact | NEEDS_VALIDATION |
| `judge-needs-validation-cited-artifact-missing` | convincing dossier whose cited `poc/` files don't exist | NEEDS_VALIDATION |
| `judge-passes-proven-finding` | cross-account read proven between two test accounts, artifacts saved | PASS |

Cases come from [`generate.py`](generate.py): edit it and run `python evals/generate.py`. Keep
fixtures fictional (`example.com`), evidence-focused and free of exploit payloads. The runner copies
the cases into a clean snapshot, because `claude plugin eval` refuses folders with hard links (a
local `.venv`). Its sandbox doesn't exist on native Windows, which is fine here: judge cases only read.

## Limits

- The trap app is ours. The chain can find bugs we didn't plant: those passes are listed as
  unexpected, for a human to check. A finding that names two items equally is listed as ambiguous.
- A hunt is non-deterministic: compare medians over three runs or more, not single runs.
- The runner measures the case file's format too: verdicts written as prose instead of
  `JUDGE H-00X: …` still count, and are reported, because `bountyproof funnel` can't read them.

The trap-app idea and the Juice Shop oracle come from
[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)'s `eval/` (MIT); this is new
code. See [docs/credits.md](../docs/credits.md).
