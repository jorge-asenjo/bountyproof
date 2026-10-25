---
description: "Phase 3 - test candidate hypotheses with a separate validator, negative control first, and classify them with captured artifacts."
argument-hint: "[hypothesis IDs]"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/03-dynamic-verification.md` from this workspace, which the engagement may have customized.
   If the workspace doesn't have it, follow `${CLAUDE_PLUGIN_ROOT}/prompts/03-dynamic-verification.md`.
4. Spawn `bountyproof:validator` agents for the candidates. Never give a candidate to the agent that proposed it.

Arguments: $ARGUMENTS
