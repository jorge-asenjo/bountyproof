---
description: "Phase 3b - run the independent evidence judge on validated findings: PASS, NEEDS_VALIDATION or DISCARD. Nothing becomes a report without PASS."
argument-hint: "[finding IDs]"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/03b-evidence-judge.md` from this workspace, which the engagement may have customized.
   If the workspace doesn't have it, follow `${CLAUDE_PLUGIN_ROOT}/prompts/03b-evidence-judge.md`.
4. Spawn a fresh `bountyproof:judge` agent and write its verdicts into `notes/case-file.md`.

Arguments: $ARGUMENTS
