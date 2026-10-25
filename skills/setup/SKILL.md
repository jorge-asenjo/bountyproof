---
description: "Phase 0 - ingest the program page, record rules, threat model and trust map, and fill notes/scope.json to arm the scope guard."
argument-hint: "<program URL>"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/00-setup-program.md` from this workspace, which the engagement may have customized.
   If the workspace doesn't have it, follow `${CLAUDE_PLUGIN_ROOT}/prompts/00-setup-program.md`.
4. The argument is the program URL. Finish by running `bountyproof scope check` on one in-scope and one out-of-scope URL (if the CLI is available) to prove the guard works.

Arguments: $ARGUMENTS
