# Phase 2: Discovery (hypotheses)

Systematic review. Output: **hypotheses with evidence dossiers** in `notes/case-file.md`.

> **Mode check.** White-box → systematic review of the cloned source (below). Black-box → no source:
> reason over the surface and the traffic captured in Phase 1. Either way the discipline is the
> same: divergent hypotheses, read-only, NO self-confirmation (Phase 3 validates). The dossier
> requirement and the evidence gate are identical.
>
> Read `reference/agent-architecture.md` and `reference/reasoning-patterns.md` first. The biggest
> gains come from sharding well and demanding evidence, not from clever prompts.

## Principles (non-negotiable)

1. **Discovery only.** A worker that finds something does NOT get to confirm it. Output is always a
   `candidate`, never `confirmed`.
2. **Shard by ARTIFACT and TRUST BOUNDARY, not by CWE.** CWE sharding overlaps and leaves gaps.
3. **A smell is not a finding.** A scary function name, sink or suspicious check is nothing without
   reachability + attacker control of the input AND of the resource/object.
4. **Every hypothesis carries a dossier** (`notes/case-file.md` section 3), including the mandatory
   *best benign alternative explanation* and a *minimal falsifiable test*.
5. **Selective retrieval, not context dumping.** Navigate with search and targeted reads.

## Step 1: shard the attack surface

From `notes/attack-surface.md` + `notes/threat-model.md`, define 4-6 shards by artifact/boundary,
adapted to THIS target. Typical shards for a web app:
- Actor/tenant resolution from request → storage.
- Server-side authorization checks; identity and role-change operations.
- Outbound fetchers, webhooks, proxies, renderers, parsers.
- Caches, queues, async jobs and side effects that bypass the normal checks.
- Non-idempotent state-changing operations (concurrency).
- Recent diffs touching checks, normalization, serialization or ownership (variant analysis).

## Step 2: assign shards to workers

Pick the cheapest division that covers the surface without overlap.

**A) Claude subagents (default).** Spawn one `bountyproof:discoverer` agent per shard, all in ONE
message so they run concurrently. Give each: the shard, the threat model, and the static auditor
prompt from `reference/worker-prompts.md` (section B). The discoverer is read-only and returns
**candidates only**. For a large deterministic fan-out (many shards, or find → verify pipelines),
drive a `Workflow` instead.

**B) Multi-model (optional, for large targets).**
- Broad read-only shards → **Gemini** in plan (read-only) mode:
  `gemini -p "<auditor prompt + shard>" --approval-mode plan --include-directories source`
  (PowerShell helper: `tools/scripts/ask-gemini.ps1 -Shard "<shard>"`).
- Repo-context / threat-model shards → **Codex** in a read-only sandbox: `codex exec "<prompt>"`
  (PowerShell helper: `tools/scripts/ask-codex.ps1 -Shard "<shard>"`).
- Respect the AI clause in `STRATEGY.md`: `AI: restricted` means no third-party worker models.
- Optional seeding: a static analyzer (e.g. `semgrep --config auto source/`) can surface candidate
  sinks. Its output is NOT a finding; triage it through the same evidence gate.

**C) Small, tightly scoped target with no lab:** skip the orchestration and do it solo. A bad
wrapper just amplifies noise.

## Step 3: the orchestrator ingests results

You own `notes/case-file.md`. For each worker hypothesis:
- Write or merge a dossier into section 3. Deduplicate against existing hypotheses.
- Reject anything that is only a smell, lacks reachability, or has no attacker control of the resource.
- For survivors, write the **benign alternative** and the **minimal falsifiable test** yourself if
  the worker's were weak. If you can't beat the benign explanation, it stays `candidate`.
- Add a row to the hypotheses table (section 2) with confidence and status.

## Step 4: prioritize for Phase 3

Order: no-auth > low-privilege > high-privilege; high impact > low; aligned with the threat model.
Run the 4-check threat-model gate NOW and drop anything out of scope before spending validation time.
Send the top candidates to Phase 3.
