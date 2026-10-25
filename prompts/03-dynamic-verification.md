# Phase 3: Validation (separate role)

Confirm or refute `candidate` hypotheses. Output: `notes/case-file.md` updated with
`confirmed` / `rejected` / `needs_validation` and the captured artifacts.

> **Mode check.** White-box → validate in the **isolated Docker lab** (`localhost`). Black-box →
> validate against the **live in-scope target**, gently and non-destructively (minimal test, in
> scope only, UA-tagged, rate-limited). Same discipline either way.
>
> This is a DIFFERENT role from discovery. The discoverer's framing is suspect by design: test
> against the *benign alternative*, not just the vulnerability hypothesis. Use the
> `bountyproof:validator` agent, or the dynamic validator prompt in `reference/worker-prompts.md`
> (section C). Never hand a finding back to the agent that proposed it.

## Setup
**White-box (lab):** 1) `docker compose up -d`  2) verify the app is running  3) create or verify
test users at each privilege level (anonymous, read-only, low-privilege, admin).
**Black-box (live):** 1) confirm the browser session is authenticated and UA-tagged  2) have
accounts A and B plus an anonymous session ready, so authorization tests are symmetric.

## The validation contract (per hypothesis)

Before testing, write down two things from the dossier:
- **Expected observation if vulnerable.**
- **Expected observation if NOT vulnerable (benign alternative).**

Then:
1. **Run negative controls / the baseline FIRST** (the same request as an authorized user, or
   against your own object) so the "vulnerable" signal means something.
2. **Test the lowest privilege first**: anonymous → read-only → low-privilege → higher.
3. Run the **minimal** test. Non-destructive only: no persistence, no data extraction, no DoS, no
   irreversible changes, and only your own test accounts and objects.
4. **Capture artifacts**: full request/response, status codes, logs, state diff.
5. **Classify**: `confirmed` (signal matches the vulnerability, not the benign explanation),
   `rejected`, or `needs_validation` (the test didn't discriminate; name the one exact fact that
   would). A test that didn't discriminate is never `confirmed`.
6. Update the dossier (section 3) and the validation log (section 4).

## Who runs it

- **1-3 candidates:** one validator, sequentially.
- **4+ candidates:** one validator per candidate, or a `Workflow`. Keep state-changing operations
  serialized (one actor mutates shared state; reads are free). On a LIVE target prefer a few careful
  sequential tests over parallel bursts.
- **Codex** can help with validation reasoning or a patch hypothesis (read-only sandbox).

## Baseline pattern (lab example)

Compare the same request across privilege levels before drawing any conclusion:

```bash
for u in "" "-u lowpriv:lowpriv123" "-u admin:admin123"; do
  curl -s -o /dev/null -w "%{http_code}  ${u:-anonymous}\n" $u "http://localhost:8080/endpoint"
done
```
On Windows PowerShell use `curl.exe` and `-o NUL`.

## Evidence
Screenshots must show the full command, the response and the terminal prompt. Browser evidence
saves to `poc/browser-output/`. Tell the user exactly which commands to run for any screenshot
they need to take themselves.

## Gate before Phase 4
Only `confirmed` findings proceed (or a candidate with a falsifiable reproducer when no lab can
reach it). Run the Evidence Judge, `prompts/03b-evidence-judge.md`, before writing any report.
