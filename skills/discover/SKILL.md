---
description: "Phase 2 - shard the surface by artifact and trust boundary and collect candidate hypotheses with dossiers from read-only discoverer agents."
argument-hint: "[shard]"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/02-static-analysis.md` from this workspace, which the engagement may have customized.
   If the workspace doesn't have it, follow `${CLAUDE_PLUGIN_ROOT}/prompts/02-static-analysis.md`.
4. Spawn one `bountyproof:discoverer` agent per shard, all in one message. Discoverers never confirm their own findings.

Arguments: $ARGUMENTS
