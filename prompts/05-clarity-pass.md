# Phase 4b: Clarity Pass (v1 → v2)

Rewrite the v1 draft into the v2 that gets submitted. The goal is a report a busy triager
understands and can reproduce in a few minutes, written the way a researcher explains a bug to a
colleague. Same facts as v1, fewer words.

This pass is about clarity and credibility, not about hiding how the report was made. If
`STRATEGY.md` says `AI: disclosure required`, the disclosure line stays in v2.

## Why
Triagers read a lot of padded, templated reports whose claims fall apart on the first replay. Dense
boilerplate, generic sections and inflated wording make them distrust the PoC before they run it.
A short, specific, first-person write-up with an exact reproducer earns the opposite reaction.

## What good looks like
- First person and concrete: "I created two accounts", "my request", "my test object".
- The bug in one or two sentences at the top: what, where, and what you demonstrated.
- Explanation woven into the steps instead of separate theory sections.
- Exact, copy-pasteable requests and values (watch for smart quotes).
- Impact in plain words, limited to what the PoC showed.
- Remediation in one or two sentences.
- Sections only as long as they need to be.

## What to cut
- Intros that explain the vulnerability class in general.
- Filler words and stock phrases ("comprehensive", "furthermore", "it is worth noting", "leverage").
- "Option A / Option B" remediation menus and before/after code blocks.
- Full HTTP exchanges formatted like documentation when two lines of curl say the same.
- Repetition between description, impact and summary.

## Accuracy guard (clearer, never stronger)
- **No new claims.** Every endpoint, ID, number, version and impact in v2 must already be in v1,
  and therefore in the evidence. Nothing gets added "to make it flow".
- **No severity creep.** Avoid "trivially", "completely", "full takeover", "any user" or "critical"
  unless the PoC literally shows it. Understated beats overstated: triagers trust the researcher who
  undersells.
- **No theoretical impact sneaking back in** ("you could probably also…", "imagine if…").
- **Keep the replayable PoC intact.** Every request, header and value stays exact.
- **Keep required lines** (the AI disclosure line when required; platform-specific placeholders
  such as `{{YWH-RXXX}}` for YesWeHack inline screenshots).

## Self-check
1. Could a triager with zero context reproduce it from v2 alone?
2. Diff the facts: list every claim in v2 and tick it against v1. Anything new or stronger → remove
   it or bring it back to v1's wording.
3. Read it once top to bottom. If a sentence doesn't help someone reproduce or assess the bug, cut it.

Save as `reports/[FINDING-ID]-v2.md`, then run Phase 4c.
