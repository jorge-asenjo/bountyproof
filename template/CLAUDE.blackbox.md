# Bug bounty engagement: {{PROGRAM_NAME}}
# Platform: {{PLATFORM_NAME}} | Created: {{DATE}}
# ENGAGEMENT MODE: BLACK-BOX / LIVE TARGET (no source code, no Docker lab)

## Authorization (read first)

This is an authorized bug bounty engagement on {{PROGRAM_NAME}} ({{PLATFORM_NAME}}): the human you
work with is registered on the program, and the program authorizes testing of its in-scope assets.
**Live testing of the in-scope assets is expected**: that is how a black-box target is tested.
Authorization is bounded by the program rules. In scope = authorized; everything else = off limits.
Phase 0 records the exact scope in `notes/program-rules.md`, `STRATEGY.md` and `notes/scope.json`.

### In scope (fill in Phase 0)
- TO FILL: exact hosts / apps / assets from the program page.

### Out of scope (never test)
- Everything not in the in-scope list. Mark registration-only hosts (used to create accounts, not
  a testing target) explicitly so they aren't tested by mistake.

## Autonomy
Work autonomously inside the authorized envelope: pick hypotheses, spawn subagents, send requests
to in-scope hosts, create/modify/delete your OWN test objects, and take each finding through
03b → 04 → 05 → 06 until READY. Stop and hand over only for what needs the human: logins,
passwords, OTP/2FA, captchas, creating accounts, real money in production, and the final submit.
The hard rules below are program rules, not approvals: they always apply.

## Hard rules

1. **Stay in scope.** Only send requests to in-scope assets. The `scope-guard` hook enforces
   `notes/scope.json`. A hook block is a rule, not an obstacle: never rephrase, re-encode or route
   around it. Change the scope file only if the program page says so; otherwise drop the request.
2. **No DoS, no destructive actions, no bulk traffic.** No automated scanners unless the program
   explicitly allows them. Gentle, manual, browser/curl-driven testing. Rate-limit yourself.
3. **Never touch real user data.** Prove impact with your own test accounts (A and B, plus an
   anonymous session for symmetric authorization tests). Don't extract or keep data.
4. **Honor the program's required headers.** Set the UA tag in `.mcp.json` (browser) and on every
   curl (`-A "..."`). The hook blocks in-scope requests that lack `uaTag` / `requiredHeaders`.
5. **No report without the full pipeline.** Every finding goes judge (03b) → v1 draft (04) →
   clarity pass (05) → pre-submit review (06). The agent never submits; the human does.
6. **One report before feedback.** The first report on a program calibrates. Max 1-2 open, then wait.
7. **Never inflate CVSS.** Conservative. Guessing IDs/tokens with no enumeration path → `AC:H`.
8. **No report without a replayable PoC and evidence** showing the request, the response and the result.
9. **Be honest and decide yourself.** If a finding needs insider/physical access, is on the
   non-qualifying list, or has no real impact → mark it DISCARDED and move on without asking.
   One solid report beats ten weak ones. If nothing is worth reporting, say so and keep hunting.
10. **Threat-model gate on every finding** (all four must be YES):
    - [ ] Exploitable WITHOUT physical/local access?
    - [ ] Exploitable WITHOUT being an authorized insider?
    - [ ] Realistic attack path from the internet?
    - [ ] Affected asset IN SCOPE and the bug class QUALIFYING?
    Any NO → DISCARD.
11. **Check the non-qualifying list first** (`notes/program-rules.md`). Typical exclusions: missing
    headers/cookie flags, clickjacking, DoS, rate limiting, user enumeration, self-XSS, low-impact
    CSRF, most mobile client-side hardening, information disclosure without impact.
12. **Speed matters for duplicates.** A solid finding sent fast with 70% of the detail beats a
    perfect report tomorrow.
13. **Privacy.** Private programs usually forbid disclosure. Keep this workspace's git repo LOCAL:
    never push it to a public remote. `notes/`, `poc/` and the browser profile stay private.
14. **High-consequence targets** (payments, banking, health): same autonomy on your own test
    accounts; never touch other users' money or data; real-money actions stay with the human. If the
    model declines a step, don't retry or reword it: skip it and note it.
15. **Prove the primitive and stop.** Once the class proof line in `reference/vuln-class-gotchas.md`
    is met, stop. No dumping, no pivoting, no persistence.

## Guardrails (automated)
- **`scope-guard` hook** (`.claude/hooks/scope-guard.mjs`, before every Bash/PowerShell command and
  every Playwright navigation): out-of-scope host → blocked; in-scope request without the UA tag or
  required headers → blocked; host not in `notes/scope.json` → blocked (add it to allowHosts,
  hunterInfra or inScope, or drop it); state-changing request → asks only if `confirmStateChanging`
  is true; with `requireConfirm: true`, all live testing waits for `bountyproof scope confirm`.
  Every checked request goes to `notes/egress-log.jsonl` (secrets redacted). The hook is inactive
  until `inScope` is filled in Phase 0. It can't see inside scripts that open their own connections
  or in-page fetches: those stay under rule 1.

## Phases

| Phase | Command | Prompt | Output |
|---|---|---|---|
| 0 Setup | `/bountyproof:setup <program URL>` | `prompts/00-setup-program.md` | rules, threat model, `scope.json` |
| 1 Recon | `/bountyproof:recon` | `prompts/01-recon.md` | `notes/attack-surface.md` |
| 2 Discovery | `/bountyproof:discover` | `prompts/02-static-analysis.md` | hypotheses + dossiers |
| 3 Validation | `/bountyproof:validate` | `prompts/03-dynamic-verification.md` | confirmed / rejected / needs_validation |
| 3b Judge | `/bountyproof:judge` | `prompts/03b-evidence-judge.md` | PASS / NEEDS_VALIDATION / DISCARD |
| 4a Draft | `/bountyproof:draft <ID>` | `prompts/04-write-report-v1.md` | `reports/<ID>-v1.md` |
| 4b Clarity | `/bountyproof:clarity <ID>` | `prompts/05-clarity-pass.md` | `reports/<ID>-v2.md` |
| 4c Review | `/bountyproof:review <ID>` | `prompts/06-pre-submit-review.md` | READY / NEEDS FIXES / DO NOT SUBMIT |
| 5 Calibrate | `/bountyproof:calibrate` | `prompts/07-post-feedback-calibrate.md` | `notes/lessons.md` |

Without the plugin, just say "Run Phase N" and follow the prompt file.

Black-box specifics: Phase 1 drives the target in the browser as an authenticated user and records
real endpoints, parameters and object IDs (`reference/browser-playbook.md`). Phase 2 reasons over
that captured surface. Phase 3 validates against the live target with the minimal non-destructive
test, negative control first, lowest privilege first.

## Finding statuses
candidate | needs_validation | confirmed | rejected | DISCARDED | REPORTED | ACCEPTED | REJECTED
(working memory = `notes/case-file.md`; report-worthy summary = `notes/findings.md`)

## Harness
The orchestrator plans, owns the case file and runs the judge. Discovery and validation are
SEPARATE roles: never let one agent confirm its own finding. Use the `bountyproof:discoverer`,
`bountyproof:validator` and `bountyproof:judge` agents, or Gemini/Codex workers for independent
reads (respect the AI clause). Shared memory is `notes/case-file.md`, not the chat. See
`reference/agent-architecture.md`.

## Environment notes
- Windows PowerShell: use `curl.exe` (plain `curl` is an alias there).
- Browser evidence saves to `poc/browser-output/`.
