# Phase 4a: Draft Report (v1)

Write a structured draft. Do NOT submit v1 directly. Use the form guide for your platform
(`reference/form-reference.md`; the platform is in `STRATEGY.md`).

## Golden rule: draft from verified facts, never over the gaps

- Every factual statement (endpoint, parameter, version, header, response content, ID, timing) must
  trace to an artifact in `notes/case-file.md` or `poc/`. If you can't point to it, it doesn't go in.
- A missing fact becomes a visible `[MISSING: what + how to get it]` placeholder and a question to the
  user, never a plausible-sounding filler. A v1 with open `[MISSING]` markers can't move to Phase 4b.
- **Impact = what the PoC demonstrated.** No "could lead to", "may allow" or "an attacker could
  potentially". If a bigger impact is plausible but unproven, go back to Phase 3 and prove it, or
  leave it out. The overclaim traps the judge recorded for this finding are banned here.
- The PoC must be replayable by a triager with zero context: exact requests (curl or raw HTTP),
  preconditions (accounts, roles, browser), expected vs actual result, and cleanup for stateful steps.
- No boilerplate: no OWASP intro paragraphs, no generic "validate all input" remediation.
- If `STRATEGY.md` says `AI: disclosure required`, add one short honest line on how AI assisted
  (e.g. "I used an AI assistant to help analyse traffic and draft this report; I reproduced every
  step manually.").

## Generate `reports/[FINDING-ID]-v1.md` with:

### Platform form fields
Fill every field listed in `reference/form-reference.md` for this platform. In short:
- **YesWeHack:** bug type (CWE), scope, endpoint, vulnerable part, part name, payload (the concrete
  value), technical environment (your real setup), application fingerprint, impact. Inline
  screenshots use `{{YWH-RXXX}}` placeholders.
- **Intigriti:** title, asset (with tier), endpoint, type (CWE), CVSS metrics, proof of concept /
  description, impact (separate field), recommended solution, severity justification, attachments.
- **HackerOne:** asset (structured scope), weakness (CWE), title, vulnerability information
  (description + steps + PoC), impact (separate field), severity, attachments.

### CVSS 3.1
Score conservatively and justify each metric. Use only verified conditions (auth required? user
interaction? scope change?). Non-guessable IDs → `AC:H`.

### Description
Use the program's required format, or the platform default:
- **YesWeHack:** Description, Exploitation, PoC, Risk, Remediation
- **Intigriti:** Description, Steps to Reproduce, PoC, Impact
- **HackerOne:** Vulnerability Information (description + PoC), Impact (separate field)

### Evidence list
List the screenshots and recordings the report needs, with the exact command or page for each.
