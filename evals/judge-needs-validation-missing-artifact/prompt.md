---
description: A plausible race condition with no captured discriminating artifact.
max_turns: 20
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Agent]
---

Before I write a report, judge finding H-001 in this engagement workspace. The files are in the current
directory: notes/case-file.md, notes/program-rules.md and notes/threat-model.md. Use the bountyproof judge
agent if you have it. Finish with exactly one line in the form `JUDGE H-001: PASS`,
`JUDGE H-001: NEEDS_VALIDATION` or `JUDGE H-001: DISCARD`.
