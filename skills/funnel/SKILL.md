---
description: "Show the evidence funnel of the current engagement - how many hypotheses were proposed, validated, passed by the judge and reported."
disable-model-invocation: true
---

Show the evidence funnel for the current engagement workspace.

1. Run the first form that works, from the workspace root:
   - `bountyproof funnel`
   - `python "${CLAUDE_PLUGIN_ROOT}/scripts/bountyproof.py" funnel`
2. Show the output as is. Then add at most two lines: where the funnel narrows most, and the single
   next action that would move a finding forward (for example the one missing fact of a
   `needs_validation` item). Don't promote anything the judge hasn't passed.
