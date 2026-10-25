---
description: "Phase 5 - learn from a real triage response and record the lesson in notes/lessons.md."
argument-hint: "<finding ID> <triage outcome>"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/07-post-feedback-calibrate.md` from this workspace, which the engagement may have customized.
   If the workspace doesn't have it, follow `${CLAUDE_PLUGIN_ROOT}/prompts/07-post-feedback-calibrate.md`.

Arguments: $ARGUMENTS
