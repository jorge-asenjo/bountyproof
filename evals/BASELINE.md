# Eval baseline

Numbers from `python evals/run.py`. Each suite run adds one row to its table, newest last. Raw
results (transcripts, case files, reports, the app's request log) stay in `evals/results/`, which is
gitignored. How each suite works and what it can't tell you: [README.md](README.md).

Plugin = the version under test: a git ref and its commit (`+` = uncommitted changes). Tokens are
medians per hunt: input (with cache writes) / output / cache reads. Time is minutes per hunt.

## Traps

The whole chain (`/bountyproof:hunt`, unsupervised) against the trap app: 16 traps that look like
bugs and aren't, and 4 real bugs. FP = traps it let through (judge PASS or a report), over traps ×
runs. TP = controls it let through, over controls × runs.

| Date | Label | Plugin | Model | Runs | FP in traps | TP in controls | Leads → validated → passed | Turns | Tokens | Min |
|---|---|---|---|---|---|---|---|---|---|---|
| 2026-11-25 | main baseline | `main` 862eee8 | `claude-sonnet-5-5` | 3/3 | 0/48 (0%) | 7/12 (58%) | 3 → 2 → 2 | 22 | 75k / 20k / 872k | 2.9 |

## Juice Shop

The whole chain against OWASP Juice Shop v20.3.0. Every finding it lets through is checked against
the challenge the app marks as solved: confirmed (the challenge got solved), refuted (it exists but
stayed unsolved: the claimed exploit didn't happen) or no challenge (the oracle can't tell). Juice Shop
is in every model's training data, so this measures honesty, not skill.

| Date | Label | Plugin | Model | Runs | Let through | Oracle confirms | Refuted | No challenge | Challenges solved | Leads → validated → passed | Turns | Tokens | Min |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-11-25 | main baseline | `main` 862eee8 | `claude-sonnet-5-5` | 3/3 | 3 | 3/3 (100%) | 0 | 0 | 2 | 1 → 1 → 0 | 25 | 90k / 20k / 849k | 2.7 |

## Judge cases

The judge on its own: the `evals/judge-*` cases through `claude plugin eval`, with and without the
plugin. A case is OK when every run with the plugin got the expected verdict.

| Date | Label | Plugin | Model | Runs per arm | Cases OK | Correct runs with plugin | Without | Cost with plugin |
|---|---|---|---|---|---|---|---|---|
| 2026-11-26 | main baseline | `main` 862eee8 | `claude-sonnet-5-5` | 3 | 8/9 | 26/27 | 25/27 | $1.96 |
