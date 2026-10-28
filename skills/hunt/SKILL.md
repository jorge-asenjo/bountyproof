---
description: "Autonomous end-to-end hunt - recon, discover, validate, judge, then draft/clarity/review every finding the judge passes; stops only at the two human gates (confirm scope, press submit)."
argument-hint: "[program URL]"
disable-model-invocation: true
---

Run the whole bountyproof pipeline autonomously in the current engagement workspace. You are the
orchestrator: you own `notes/case-file.md` and sequence the phases, delegating discovery, validation
and judging to SEPARATE agents. Keep going on your own through every phase; stop only at the two
human gates below. This is the one-command version of running `/bountyproof:recon` -> `discover` ->
`validate` -> `judge` -> `draft` -> `clarity` -> `review` by hand.

## Preconditions
1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof workspace:
   tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`. The hard rules and the
   `scope-guard` hook apply to every step here; a hook block is a rule, never route around it.

## Gate 1 - scope (human only)
3. If `inScope` in `notes/scope.json` is empty, Phase 0 isn't done: run it first - follow
   `prompts/00-setup-program.md` (workspace, else `${CLAUDE_PLUGIN_ROOT}/prompts/00-setup-program.md`),
   using the program URL argument if given, else `notes/program-raw.md`.
4. Then, if `requireConfirm` is true and the scope isn't confirmed (empty or stale `confirmedScope`, or
   a scope-guard block says "Scope not confirmed"), STOP and hand over: the hook forbids you from
   confirming. Tell the human to review `notes/scope.json` against `notes/program-raw.md` and run
   `bountyproof scope confirm` (or `tools/scripts/confirm-scope.ps1`) in their own terminal, then
   re-run `/bountyproof:hunt`. Proceed past here only once scope is confirmed (or `requireConfirm`
   is false).

## Hunt (autonomous - no stops)
5. **Recon** - follow `prompts/01-recon.md` (workspace, else `${CLAUDE_PLUGIN_ROOT}/prompts/01-recon.md`).
   Fan out read-only subagents on a large surface. Output -> `notes/attack-surface.md`.
6. **Discover** - follow `prompts/02-static-analysis.md`. Spawn one `bountyproof:discoverer` agent per
   shard (shard by artifact + trust boundary), all in one message. Discoverers are read-only and never
   confirm their own leads. Collect hypotheses + dossiers into `notes/case-file.md`.
7. **Validate** - follow `prompts/03-dynamic-verification.md`. Spawn `bountyproof:validator` agents for
   the candidates; never give a candidate to the agent that proposed it. Negative control first,
   lowest privilege first. Classify confirmed / rejected / needs_validation in the case file.
8. **Judge** - follow `prompts/03b-evidence-judge.md`. Spawn a fresh `bountyproof:judge` agent and
   write its PASS / NEEDS_VALIDATION / DISCARD verdicts into `notes/case-file.md`.

## Report every PASS finding (autonomous loop)
9. For each finding whose judge verdict is PASS, strongest first, run the full report trio without
   stopping between findings:
   - **Draft** - follow `prompts/04-write-report-v1.md` -> `reports/<ID>-v1.md`. Verified facts only;
     `[MISSING]` for gaps, never filler.
   - **Clarity** - follow `prompts/05-clarity-pass.md` -> `reports/<ID>-v2.md`. Same facts, concise
     first person.
   - **Review** - follow `prompts/06-pre-submit-review.md`, using a fresh `bountyproof:judge` agent as
     the second opinion -> READY / NEEDS FIXES / DO NOT SUBMIT. On NEEDS FIXES, apply them and
     re-review the same ID until READY or DO NOT SUBMIT.

## Gate 2 - submit (human only)
10. When every PASS finding is READY or DO NOT SUBMIT, STOP. Run `bountyproof funnel` (or
    `python "${CLAUDE_PLUGIN_ROOT}/scripts/bountyproof.py" funnel`) and show it, then list each READY
    finding with its severity and the path to `reports/<ID>-v2.md`. The agent never submits; the human
    reviews and submits. Per `CLAUDE.md` rule 6, recommend submitting the single strongest report
    first and waiting for triage to calibrate before sending the rest.
11. If nothing reached a report, say so plainly (one solid report beats ten weak ones - `CLAUDE.md`
    rule 9): show the funnel and name the single next action that would move the best lead forward
    (for a `needs_validation` item, its one missing fact).

## Throughout
- Shared memory is `notes/case-file.md`, not this chat. Write a canonical summary there between phases.
- Discovery, validation and judging stay separate roles: never let one agent confirm its own finding;
  always a fresh judge.
- Hand over to the human only for: scope confirmation (Gate 1), the final submit (Gate 2), logins /
  OTP / captcha / account creation, and real-money actions in production. Everything else inside the
  authorized envelope: proceed autonomously.
- Resume, don't redo: if a phase's output already exists and is complete in the case file, extend it
  rather than start over.
- Large or complex target: you may run discover/validate as a deterministic `Workflow` instead of
  inline subagents - see `reference/agent-architecture.md`.

Arguments: $ARGUMENTS
