# Evals

A seed benchmark for the evidence judge, run with Claude Code's native
[`claude plugin eval`](https://code.claude.com/docs/en/plugin-evals.md). Each case seeds a fictional
engagement workspace (program rules, threat model, scope, case file) and asks for a verdict on one
finding. The runner repeats every case with and without the plugin, so the score difference shows
what bountyproof's judge adds over the same model on its own.

| Case | The finding | Expected verdict |
|---|---|---|
| `judge-rejects-reachability-only` | "cross-account access" backed only by a 200 status, no foreign data | not PASS |
| `judge-rejects-already-obtainable` | "disclosure" of data the role already sees in the UI | not PASS |
| `judge-rejects-out-of-scope-by-design` | solid cross-tenant read on an asset the program excludes | not PASS |
| `judge-rejects-insider-precondition` | injection that needs staff access to a trusted console | not PASS |
| `judge-needs-validation-missing-artifact` | plausible race with no captured artifact | NEEDS_VALIDATION |
| `judge-needs-validation-cited-artifact-missing` | convincing dossier whose cited `poc/` files don't exist | NEEDS_VALIDATION |
| `judge-passes-proven-finding` | cross-account read proven between two test accounts, artifacts saved | PASS |

Graders: a regex on the final `JUDGE H-001: …` line (weight 3), a check that no slop case gets PASS,
and an indicator of whether the plugin's `judge` agent was used.

Latest results are in the main [README](../README.md#evals).

## Run

```bash
claude plugin eval . --scaffold --trust-plugin             # 7 cases × 3 runs × with/without plugin
claude plugin eval . --scaffold --trust-plugin --runs 1 --ablation none   # quick smoke test
```

`--scaffold` runs each case's `scaffold.sh`, which only writes the fixture files into the run's empty
workspace. Results land in `evals/results/` (gitignored). A full run is about 42 agent sessions and
counts against your plan or API usage.

Run it from a clean checkout: the runner refuses plugin folders that contain hard links, which a
local `.venv` can introduce.

## Adding cases
Edit `evals/generate.py` and run `python evals/generate.py`. Keep fixtures fictional (`example.com`),
evidence-focused, and free of exploit payloads. Next steps for the suite: cases built from publicly
disclosed reports (valid and invalid), and pipeline cases against the `lab/` target.
