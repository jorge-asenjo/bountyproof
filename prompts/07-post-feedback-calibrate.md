# Phase 5: Post-Feedback Calibration

> **Close the loop first.** Check that every confirmed finding is logged in
> `notes/submissions-log.md` as SUBMITTED with its platform report ID. A finished draft that was
> never sent is worth nothing. This phase runs when a REAL triage response arrives, and what it
> learns goes into `notes/lessons.md`.

## If ACCEPTED
- Record what worked (framing, evidence, pacing) in `notes/lessons.md`.
- Reuse the same structure for the next reports on this program.
- Move to the next finding.

## If REJECTED as low quality / unclear
- Which claims did the triager question? Trace each one back to the evidence.
- Re-run the judge (03b) on the original finding. If a claim had no artifact, that's the lesson.
- Tighten the clarity pass for next time. Don't reply with more words; reply with new evidence or
  not at all.

## If REJECTED as out of scope / not a vulnerability
- Re-read the program rules and the threat model. WHY was it rejected?
- Update `notes/threat-model.md`.
- Filter the remaining findings with the same logic and mark similar ones DISCARDED.

## If REJECTED as duplicate
- Note the referenced report.
- Search the program's known issues and public reports for related entries.
- Filter the remaining findings and note what the dup-check missed.

## If the triager gave format feedback
- Copy the exact feedback into `notes/lessons.md`.
- Adjust the report template and apply it to every pending report.

## Always
- Update the finding's status in `notes/findings.md` and `notes/submissions-log.md`.
- Write the lesson in one or two lines: what happened, what changes next time.
