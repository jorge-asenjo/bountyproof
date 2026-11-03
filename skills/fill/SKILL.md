---
description: "Phase 4d - fill a READY report into the platform's report form in your own Chrome (Claude in Chrome extension) and stop before submit. You read it and press submit."
argument-hint: "<finding ID>"
disable-model-invocation: true
---

Run this phase of the bountyproof pipeline in the current engagement workspace.

1. If there is no `notes/scope.json` in the current directory, this is not a bountyproof
   workspace: tell the user to create one with `/bountyproof:new` and stop.
2. Read `CLAUDE.md` (engagement mode and hard rules) and `notes/case-file.md`.
3. Follow `prompts/06b-fill-report-form.md` from this workspace, which the engagement may have
   customized. If the workspace doesn't have it, follow
   `${CLAUDE_PLUGIN_ROOT}/prompts/06b-fill-report-form.md`.
4. This runs even when `notes/hunter-profile.md` says `Fill with Claude in Chrome: off`: that switch
   only decides whether `/bountyproof:hunt` fills the form on its own. The agent never submits; the
   human does.

Arguments: $ARGUMENTS
