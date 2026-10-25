# Reasoning Patterns for Vulnerability Discovery

> Reverse-engineered from documented real cases where LLM agents found long-lived bugs in widely
> used software: o3/ksmbd CVE-2025-37899, Big Sleep/SQLite `seriesBestIndex`, Anthropic×Mozilla
> Firefox (22 CVEs), OpenAI Codex Security, Protect AI Vulnhuntr, XBOW (Druid SSRF, 2FAuth XSS).
> All of these are public write-ups; read the originals for the full details.

## The one meta-principle (most important)

**The harness must give the model LESS AMBIGUITY, not more code.** In every solid public success the
agent won inside a *well-shaped problem*: a seed diff, an isolated subsystem, a restricted goal, a
pre-joined source→sink path, or an unambiguous verifier. Where that shaping is missing, the process
degrades into expensive guessing and noise. This is exactly why we shard by artifact+trust-boundary,
separate discovery from validation, and demand a falsifiable test (see `reference/agent-architecture.md`).

## The cognitive moves (use these as the actual thinking, not "look for bugs")

| # | Pattern | The mental move | Bug classes | Trigger phrase to give the worker | What verifies it |
|---|---------|-----------------|-------------|-----------------------------------|------------------|
| 1 | **Lifecycle tracking under concurrency** | Follow one object across simultaneous *legal* paths: "who thinks it's the last owner, and who else can still touch it?" | UAF, races, teardown/setup races | "Track ownership/refs of `<obj>` across legal concurrent paths. Find a schedule where one path frees it while another still dereferences it. Emit the exact schedule." | A concrete `free`/`put` in path A and a later deref in path B on the same alias. |
| 2 | **Variant analysis from a sibling fix/diff** | Treat a fix/diff as a partial spec of a broken invariant; hunt sibling paths where the same invariant still fails at HEAD | memory safety, parser/planner edge cases, **logic/SSRF siblings** | "Given this fix diff, find sibling paths in the current code where the same invariant can still fail." | Same semantic shape in a path the original patch didn't touch. |
| 3 | **Sentinel / invariant breaker** | Enumerate special values (`-1`, NULL, "reserved", ROWID, odd flags) and prove every consumer guards them before indexing/shifting/truncating/dereferencing | OOB, under/overflow, truncation, parser bugs | "List all sentinel/special values for each field, then prove every consumer guards them before use." | A consumer uses the field as index/size/pointer without handling the sentinel. |
| 4 | **Source→sink with object context** | Not "is there a dangerous sink?" but "can THIS attacker-controlled value keep its power through wrappers/classes/callbacks all the way to the sink?" | **SSRF, IDOR/BOLA, injection, path traversal, XSS**, file abuse | "Follow this attacker-controlled value from source to privileged sink. Ignore blocked paths unless you can prove a bypass." | A PoC that reaches the sink in real context. |
| 5 | **Errors/validators as sensors, not just oracles** | Turn every failure/crash/error into an observation that *reduces hypotheses* (module absent, endpoint exists, crash moved, flag appeared) | anything needing iterative exploration | "Treat every failure mode as a sensor. After each distinct error, produce ONE updated hypothesis and ONE next experiment." | The hypothesis changes after each error and converges on a real surface. |
| 6 | **Minimal testcase BEFORE root cause** | Don't explain first; build the smallest input that triggers the bad state, *then* re-explain the program anchored to the bug | memory, logic, parser, web | "First make it fail with the smallest input you can. Only after reproduction, explain root cause." | Short stable reproducer; the causal explanation visibly sharpens after repro. |
| 7 | **Separate crash-hunting from security triage** | "Interesting crash/anomaly" and "exploitable vuln" are distinct stages with extra validation between them | browsers, parsers, big codebases, **noisy web findings** | "Classify candidates: anomaly-only / memory-safety w/ attacker control / authz-integrity impact / non-security bug." | Noisy candidates drop before reporting; maintainer-channel precision rises. |
| 8 | **Candidate patch as a comprehension check** | Forcing the agent to propose the fix reveals whether it actually understood the broken invariant | bugs with a localizable root cause | "Propose the smallest patch that restores the invariant. Verify the bug dies AND intended behavior still passes." | Fix kills the bug without breaking basic tests/behavior. |

## Which patterns transfer to web / authz targets

Most documented *reasoning* is memory/code bugs, but these transfer directly to web/authz hunting:
- **#4 source→sink with object context** → IDOR/BOLA (follow the object ID from request to the
  storage read), SSRF (follow a URL param to the outbound fetcher), XSS (follow input to a sink).
- **#2 variant analysis** → an SSRF/authz bug "rhymes" with a past CVE on the same app (XBOW/Druid:
  tried historical SSRF endpoints, then guessed a hidden proxy plugin existed).
- **#5 errors as sensors** → differential responses (200 vs 403 vs 404), an app error revealing a
  hidden endpoint, timing — each error narrows the hypothesis. This is the negative-control discipline.
- **#6 minimal testcase + binary verifier** → XBOW's `victim-goto` returned a flag only on real
  `alert("XSS")`; build an unambiguous "vulnerable vs benign" check before believing a finding.
- **Symmetry break (a flavor of #2/#4)** → compare two paths that *should* be symmetric: read vs
  write authz, account A vs account B, owner vs non-owner. Asymmetry = the bug. (Core IDOR move.)
- **"Looks like a feature until wired to the right sink"** (2FAuth SVG→XSS) → don't dismiss normal
  functionality; ask what dangerous format/sink it quietly accepts.

## Anti-lessons (what does NOT generalize — stay honest)

- **No "general autonomy."** Success came from heavy problem-shaping (cut scope, seed diff, isolated
  subsystem, restricted goal, custom verifier). Claims of "the model just reasoned its way there" omit the crutches.
- **Crash ≠ vuln; candidate report ≠ useful finding.** Anthropic: 112 reports → 22 vulns (~20%, and
  Mozilla asked for bulk submission of not-fully-validated crashes). Model the discovery→validation
  funnel as part of the system, not as afterthought triage. (This is our evidence gate.)
- **Part of the performance is prior knowledge / memory, not "pure" reasoning.** Big Sleep "knew"
  SQLite; XBOW reused historical CVEs. Brand-new targets with no prior patterns generalize worse.
- **Impressive ≠ calibrated.** Heelan's 8/100 trials and Anthropic's 112→22 are honest signal/noise;
  much vendor reporting is aggregate or benchmark-only. Don't compare reliability via storytelling.
