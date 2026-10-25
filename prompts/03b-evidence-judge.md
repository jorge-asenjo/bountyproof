# Phase 3b: Evidence Judge (the gate before any report)

A short, mandatory gate between validation and report writing. Its only job: stop weak findings
from becoming reports. Run it with the `bountyproof:judge` agent, which sees the case file but did
not take part in discovery or validation. See `reference/agent-architecture.md` §4.

> The judge looks at the finding with DIFFERENT framing than the discoverer. Agreement between
> workers is not evidence. Observable proof is.

## 1. Demand all three, for each finding

1. **Necessary exploitation conditions**, spelled out. Who must the attacker be? What must be true?
   If a precondition is "attacker is admin", "local access" or "authorized insider" → likely DISCARD.
2. **Best benign alternative explanation**, and why the captured evidence beats it. If the benign
   explanation still fits the observed behavior → not confirmed.
3. **The discriminating test result**: the actual artifact (request/response, log, state diff) that
   separates "vulnerable" from "benign". No artifact → not confirmed.

If any of the three is missing, the status drops to `needs_validation` or `candidate` and no report
is written. A `needs_validation` record names the **one exact unresolved fact** blocking
confirmation and carries **no severity**: a verdict without that fact is a guess.

## 2. Check the class gotchas

Open `reference/vuln-class-gotchas.md` at the finding's class (if the YesWeHack claude-kit plugin is
installed, `/ywh:gotchas <class>` gives an independent second list). Write in the case file:
- **Proof line met?** Quote the artifact that satisfies it. Not met → `candidate`, keep digging.
- **Matches an N/A pattern?** → DISCARD, unless the program explicitly lists it as qualifying.
- **Overclaim traps:** which impact claims the evidence does NOT support. They are banned from the
  report's impact section, its title and its CVSS vector.

## 3. The "does this actually pay" gate

The four ways technically correct findings get closed for nothing. Run them before drafting.

1. **Reachability is not impact.** Have you shown the final primitive, or only that an endpoint is
   reachable or a value is loosely validated? Each class has a discriminator, for example:
   - Object-level authorization → an actual cross-account read or write between your own accounts
     A and B, not "the ID was accepted".
   - Redirect / OAuth handling → the code or token actually delivered to a host you control, not
     "the path was accepted".
   - Server-side request handling → a measurable differential or a hit on an endpoint you control,
     not "the URL was saved".
   - Authorization logic → a privilege boundary actually crossed, not "the check is missing in code".
   Only reachability → status `candidate`; keep working toward the primitive or drop it.
2. **Already obtainable?** Can the attacker's role already get this information or perform this
   action through a legitimate path at the same privilege level? Then it is not a leak → DISCARD. A
   finding only counts if it crosses a boundary the attacker couldn't cross otherwise.
3. **By design or out of scope?** Re-read the program's out-of-scope, known-issues and "won't fix"
   sections. If the root cause is something the program considers by design or someone else's
   responsibility (for example "tenant isolation is the reverse proxy's job") → DISCARD.
4. **Duplicate risk.** Is this the obvious, first-thing-a-scanner-finds bug on a saturated target?
   Then find a novel angle, or accept it will probably be a duplicate and send it fast with 70% of
   the detail rather than perfect and late.

## 4. The threat-model gate (4 checks, non-negotiable)

- [ ] Exploitable WITHOUT physical or local access?
- [ ] Exploitable WITHOUT being an authorized insider?
- [ ] Realistic attack path from the internet?
- [ ] Affected component is UNTRUSTED in the program's threat model?

Any NO → DISCARD. Don't ask the user.

## 5. Conservative severity

Score CVSS conservatively (`reference/cvss-cheat-sheet.md`). If exploitation needs guessing names,
IDs or tokens with no real enumeration mechanism → Attack Complexity = HIGH (for example an
authorization bug on a random UUID is `AC:H` unless you show where victims' IDs leak). Score only
conditions you verified. Under-scoring and letting the triager raise it beats the reverse.

## Output

Write the verdict for each finding into `notes/case-file.md`:

```
JUDGE H-00X: PASS | NEEDS_VALIDATION (<the one fact>) | DISCARD (<reason>)
```

Only PASS findings move to Phase 4a. Everything else stays in the case file with an honest status.
If nothing passes, say "nothing worth reporting yet" and keep hunting.
