# Bug bounty engagement: {{PROGRAM_NAME}}
# Platform: {{PLATFORM_NAME}} | Created: {{DATE}}
# ENGAGEMENT MODE: WHITE-BOX / SOURCE-AVAILABLE (clone repos, prove in a local Docker lab)

## Authorization (read first)

This is an authorized bug bounty engagement on {{PROGRAM_NAME}} ({{PLATFORM_NAME}}): the human you
work with is registered on the program. This is a SOURCE-AVAILABLE target: analysis happens on the
cloned source, and every finding is proven in a **local Docker lab**, NOT against the program's
production servers. Reporting is bounded by the program rules and scope (Phase 0).

## Hard rules

1. **Never test the program's live/production servers.** Reproduce and prove everything in the local
   lab. (If the program also authorizes live testing of specific hosts, treat those as a black-box
   engagement and keep them strictly in scope. The default is lab-only.)
2. **No report without the full pipeline.** Judge (03b) → v1 draft (04) → clarity pass (05) →
   pre-submit review (06) → form filled (06b). The agent never submits; the human presses submit.
3. **One report before feedback.** The first report on a program calibrates.
4. **Never inflate CVSS.** Be conservative.
5. **No report without a replayable PoC and evidence** from the lab.
6. **Never skip the program rules and the threat model.** Phase 0 is mandatory.
7. **Be honest and decide yourself.** Needs admin/physical/insider access, mitigated elsewhere, or
   would be closed as informative / won't fix → mark DISCARDED and move on without asking. If
   nothing is worth reporting, say so and keep hunting.
8. **Threat-model gate on every finding** (all four must be YES):
   - [ ] Exploitable WITHOUT physical/local access?
   - [ ] Exploitable WITHOUT being an authorized insider?
   - [ ] Realistic attack path from the internet?
   - [ ] Affected component UNTRUSTED in the program's threat model?
   Any NO → DISCARD.
9. **Know what is trusted.** Phase 0 maps every component TRUSTED/UNTRUSTED from the program's own
   docs into `notes/threat-model.md`. Never report bugs in trusted components.
10. **Speed matters for duplicates.** When new code lands, review the diff first. A solid finding
    sent fast with 70% of the detail beats a perfect report tomorrow.
11. **Privacy.** Keep this workspace's git repo LOCAL for private programs. `notes/`, `poc/`, cloned
    `source/` and any secrets stay private.
12. **Prove the primitive and stop.** Once the class proof line in `reference/vuln-class-gotchas.md`
    is met in the lab, describe the impact; don't build further exploitation to "show reach".

## Guardrails (automated)
- **`scope-guard` hook** (`.claude/hooks/scope-guard.mjs`): before every Bash/PowerShell network
  command and Playwright or Claude in Chrome navigation it checks `notes/scope.json`. In white-box, `inScope` = the lab
  hosts and the program's production domains go in `outOfScope`, so rule 1 is enforced by code:
  production → blocked; unknown host → blocked. Checked requests are logged to
  `notes/egress-log.jsonl`. Never route around a block.
- **Claude in Chrome** is the human's own Chrome, for the platform's report form only: the hook
  blocks it from in-scope hosts and asks the human before any click described as a submit.

## Phases

| Phase | Command | Prompt | Output |
|---|---|---|---|
| 0 Setup | `/bountyproof:setup <program URL>` | `prompts/00-setup-program.md` | rules, trust map, lab, `scope.json` |
| 1 Recon | `/bountyproof:recon` | `prompts/01-recon.md` | `notes/attack-surface.md` |
| 2 Discovery | `/bountyproof:discover` | `prompts/02-static-analysis.md` | hypotheses + dossiers |
| 3 Validation | `/bountyproof:validate` | `prompts/03-dynamic-verification.md` | lab-verified verdicts |
| 3b Judge | `/bountyproof:judge` | `prompts/03b-evidence-judge.md` | PASS / NEEDS_VALIDATION / DISCARD |
| 4a Draft | `/bountyproof:draft <ID>` | `prompts/04-write-report-v1.md` | `reports/<ID>-v1.md` |
| 4b Clarity | `/bountyproof:clarity <ID>` | `prompts/05-clarity-pass.md` | `reports/<ID>-v2.md` |
| 4c Review | `/bountyproof:review <ID>` | `prompts/06-pre-submit-review.md` | READY / NEEDS FIXES / DO NOT SUBMIT |
| 4d Fill | `/bountyproof:fill <ID>` | `prompts/06b-fill-report-form.md` | the platform's form filled in your Chrome, not sent |
| 5 Calibrate | `/bountyproof:calibrate` | `prompts/07-post-feedback-calibrate.md` | `notes/lessons.md` |

Without the plugin, just say "Run Phase N" and follow the prompt file.

White-box specifics: Phase 0 clones the repos into `source/` and sets up `docker/`. Phase 2 is a
systematic, read-only review of the source, sharded by artifact and trust boundary. Phase 3 proves
each candidate in the lab: negative control first, lowest privilege first, non-destructive.

## Finding statuses
candidate | needs_validation | confirmed | rejected | DISCARDED | REPORTED | ACCEPTED | REJECTED
(working memory = `notes/case-file.md`; report-worthy summary = `notes/findings.md`)

## Harness
The orchestrator plans, owns the case file and runs the judge. Discovery (Phase 2) and validation
(Phase 3) are SEPARATE roles: never let one agent confirm its own finding. Use the
`bountyproof:discoverer`, `bountyproof:validator` and `bountyproof:judge` agents, or Gemini/Codex
workers in read-only mode for large codebases (respect the AI clause). See
`reference/agent-architecture.md` and `reference/worker-prompts.md`.

## Environment notes
- Windows PowerShell: use `curl.exe`. Git Bash + Docker: prefix `MSYS_NO_PATHCONV=1` for paths.
