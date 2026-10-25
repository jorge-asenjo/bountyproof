# Phase 4c: Pre-Submit Review

Ends with ONE verdict. Output this block (omit empty sections, except VERDICT):

```
VERDICT: READY | NEEDS FIXES | DO NOT SUBMIT

## Critical (blocks submission)
- [issue] → [fix]
## Major
- [issue] → [fix]
## Minor
- [issue] → [fix]
```

- **DO NOT SUBMIT**: any threat-model NO, asset or class out of scope or on the non-qualifying list,
  testing broke a program rule, or the class proof line isn't met. → status DISCARDED, or back to Phase 3.
- **NEEDS FIXES**: any Critical/Major item fixable from existing evidence. Fix it, then re-run 06.
- **READY**: no Critical/Major left. Only then does the human copy it into the platform form and
  press submit. The agent never submits.

## Duplicate check (run BEFORE the verdict)
Five minutes here saves the worst outcome: a duplicate sent late. For this finding's class and asset:
- **Platform disclosures:** the program's public reports (HackerOne Hacktivity; the program's
  changelog or "already reported" notes on YesWeHack; Intigriti reports aren't public, so rely on
  the program's known-issues list).
- **Web:** search for `<target> <bug class>` and `<target> bug bounty writeup <class>`. A public
  write-up of the same bug on the same asset almost certainly means a duplicate.
- **Known issues:** re-read `notes/program-rules.md` for "already known" entries.
- **Decide:**
  - Clear prior public report of the same bug on the same asset → **DO NOT SUBMIT** (or report only a
    genuinely novel variant or chain, stated as such).
  - Saturated target + commodity class → find a novel angle, or send fast with 70% of the detail and
    note `dup_risk` in the case file.
  - No sign of a prior report → proceed.
Record where you searched and what you found in the case file, so Phase 07 can calibrate.

## Independent second opinion
Spawn a fresh `bountyproof:judge` agent on the v2 text with `notes/program-rules.md` as the rules
(if the YesWeHack claude-kit plugin is installed, `/ywh:triage` works too). It is a separate
reviewer with no stake in the finding.
- Its Critical items are blockers unless you can show evidence that refutes them.
- Resolve disagreements with evidence, not by majority and not by softening wording.
- Flags about invented facts, theoretical impact or an unreplayable PoC are never advisory.

## Threat-model gate (ALL must be YES, or DO NOT SUBMIT)
- [ ] Exploitable WITHOUT physical/local access?
- [ ] Exploitable WITHOUT being an authorized insider?
- [ ] Realistic attack path from the internet?
- [ ] Affected component is UNTRUSTED in the threat model?

## Program alignment
- [ ] All program rules read?
- [ ] Component IN SCOPE (matches `notes/scope.json` inScope, not outOfScope)?
- [ ] NOT on the "not a vulnerability" list?
- [ ] NOT mitigated by operational or infrastructure measures?
- [ ] Claimed severity within the program's cap for the class?
- [ ] AI clause honoured (disclosure line present if required)?
- [ ] Duplicate check run and recorded?

## Accuracy
- [ ] Every factual claim traces to evidence in the case file / `poc/`? No `[MISSING]` left?
- [ ] Impact = only what the PoC demonstrated (no "could lead to")?
- [ ] Class proof line from `reference/vuln-class-gotchas.md` met and quoted in the case file?
- [ ] None of the recorded overclaim traps appear in the impact, the title or the CVSS vector?
- [ ] v2 adds no claim and no stronger wording than v1?

## Clarity
- [ ] The bug is clear from the first two sentences?
- [ ] First person, concrete, no generic class explanation?
- [ ] Remediation in one or two sentences, no option menus?
- [ ] No filler and no repeated content across sections?

## Technical
- [ ] PoC replayable step by step by a triager with zero context?
- [ ] CVSS conservative, only verified conditions (non-guessable IDs → AC:H)?
- [ ] Versions, file paths and line numbers correct?
- [ ] Payloads copy-pasteable (no smart quotes, no broken unicode)?

## Evidence
- [ ] Screenshots or recordings captured, showing request + response (+ prompt for terminal shots)?
- [ ] Evidence referenced in the text and attached the way the platform expects?
- [ ] Cleanup noted for stateful PoCs (created objects, uploaded files)?

## Pacing
- [ ] First report on this program? Submit only this one and wait for feedback.
- [ ] Otherwise: feedback received on the previous one? Max 1-2 open reports before waiting.

## Form fields
- [ ] All mandatory fields filled per `reference/form-reference.md`?
- [ ] Payload is a concrete value, not a template?
- [ ] Technical environment describes your real setup?
