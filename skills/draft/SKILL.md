---
description: "Phase 4a - draft a structured v1 report from verified facts only, with [MISSING] placeholders instead of filler."
argument-hint: "<finding ID>"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/04-write-report-v1.md` from this workspace, which the engagement may have customized.
   If the workspace doesn't have it, follow `${CLAUDE_PLUGIN_ROOT}/prompts/04-write-report-v1.md`.
4. Only draft findings whose judge verdict is PASS.

Arguments: $ARGUMENTS
