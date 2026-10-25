# Case File — canonical shared memory

> This is the source of truth for the engagement, NOT the chat transcript. Workers and the
> orchestrator read and write canonical summaries here. See `reference/agent-architecture.md`.
> Rule: a finding does not exist until it has a complete evidence dossier (section 3).

## 1. Facts (established, not speculative)

What we KNOW about the target: stack, auth model, tenant model, entry points, trust boundaries
confirmed in Phase 1. Keep terse and verifiable. Cite `file:line` or observed behavior.

- 

## 2. Hypotheses (the work queue)

| ID | Class | Shard / artifact | Trust boundary | Confidence | Status |
|----|-------|------------------|----------------|------------|--------|
| H-001 | | | | low/med/high | candidate |

> **Status vocabulary** (Cloudflare harness distinction — keep the verdicts sharp):
> - `confirmed` — complete trace (source path or observed request→response) **and** a bounded,
>   observed result. Only a confirmed finding gets a severity.
> - `needs_validation` — a source-grounded lead blocked on **one exact unresolved fact** (name it in
>   the dossier). **No severity** until that fact is resolved. This replaces vague "inconclusive":
>   you must be able to write the single thing that would move it to confirmed or rejected.
> - `rejected` — a disproved claim: the discriminating test came back benign. Record why, so a later
>   pass doesn't re-chase it.
> - `candidate` — hypothesis not yet tested.

## 3. Evidence dossiers (one per hypothesis)

### H-001 — <title>
- **Affected asset / trust boundary:**
- **Code path (source → transforms → checks → sink/action):**
- **Preconditions:**
- **Attacker control of input:**
- **Attacker control of resource/object:**
- **Expected observation if vulnerable:**
- **Best benign alternative explanation:** *(mandatory — if you can't beat it, don't promote)*
- **Minimal falsifiable test (discriminates vuln vs benign):**
- **Validation result + artifacts:** *(request/response, logs, state diff — fill in Phase 3)*
- **Status:** candidate / confirmed / needs_validation / rejected
- **If `needs_validation` — the ONE exact unresolved fact:** *(e.g. "whether B's object id is
  enumerable without an auth leak" — no severity until resolved)*
- **Tentative severity (conservative, ONLY if confirmed):**

## 4. Validation log

| ID | Test run | Negative control | Result | Artifact ref |
|----|----------|------------------|--------|--------------|
| | | | | |

## 5. Open questions / next actions

- 
