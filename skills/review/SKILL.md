---
description: "Phase 4c - pre-submit review ending in one verdict: READY, NEEDS FIXES or DO NOT SUBMIT, with a duplicate check and an independent second opinion."
argument-hint: "<finding ID>"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/06-pre-submit-review.md` from this workspace, which the engagement may have customized.
   If the workspace doesn't have it, follow `${CLAUDE_PLUGIN_ROOT}/prompts/06-pre-submit-review.md`.
4. Use a fresh `bountyproof:judge` agent as the second opinion. The agent never submits; the human does.

Arguments: $ARGUMENTS
