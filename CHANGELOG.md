# Changelog

## 0.1.0 (unreleased)

First public release.
- Claude Code plugin: phase skills (`/bountyproof:setup` … `/bountyproof:calibrate`), `new` and
  `funnel` skills, `discoverer` / `validator` / `judge` agents, scope-guard hook.
- Workspace template for black-box (live) and white-box (source + Docker lab) engagements.
- Phase 4b is now a clarity pass (same facts, concise first-person write-up).
- CLI: `new`, `start`, `scope check | confirm | hash`, `funnel`, `doctor`. Standard library only.
- Scope guard: `requireConfirm` human confirmation gate, dry-run mode for `scope check`, plugin copy
  defers to the workspace copy.
- Radar: GitHub Actions templates that watch platforms and score new programs.
- Demo lab with OWASP Juice Shop.
- Seed eval suite for the evidence judge (7 cases) with first results in the README.
