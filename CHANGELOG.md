# Changelog

## 0.1.0 (unreleased)

First public release.
- Claude Code plugin: phase skills (`/bountyproof:setup` … `/bountyproof:calibrate`), `new` and
  `funnel` skills, `discoverer` / `validator` / `judge` agents, scope-guard hook.
- Workspace template for black-box (live) and white-box (source + Docker lab) engagements.
- Phase 4b is now a clarity pass (same facts, concise first-person write-up).
- CLI: `new`, `start`, `scope check | confirm | hash`, `funnel`, `doctor`, `onboard`, `radar init`.
  Standard library only.
- Onboarding: `bountyproof onboard` (and `/bountyproof:onboard`) detects hardware, tools and phones
  over USB, asks about platform accounts, devices and limits, and saves a hunter profile. New
  workspaces get it as `notes/hunter-profile.md`; Phase 0 plans with it.
- `bountyproof radar init` writes Radar with the profile filled into its fit score and, with the
  GitHub CLI, creates the private repo, sets the secrets, picks a private ntfy topic and sends a test
  alert to your phone.
- Black-box workspaces start with `requireConfirm: true`: no live testing until the human runs
  `bountyproof scope confirm`, and the scope guard blocks the agent from running it.
- README reframed around the agent team and the path from onboarding to a submitted report;
  `WINS.md` for real payouts.
- Scope guard: `requireConfirm` human confirmation gate, dry-run mode for `scope check`, plugin copy
  defers to the workspace copy.
- Radar: GitHub Actions templates that watch platforms and score new programs.
- Demo lab with OWASP Juice Shop.
- Seed eval suite for the evidence judge (7 cases) with first results in the README.
