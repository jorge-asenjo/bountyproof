"""The evidence funnel: how many hypotheses survive each gate of an engagement.

Reads ``notes/case-file.md``: the hypotheses table (last column = status) and the judge's
``JUDGE H-00X: PASS | NEEDS_VALIDATION | DISCARD`` lines. Statuses are case-sensitive on purpose:
lowercase ``rejected`` is a validation result, uppercase ``REJECTED`` is a platform outcome.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_ROW = re.compile(r"^\|\s*(H-\d+)\s*\|(.*)\|\s*$")
_JUDGE = re.compile(r"JUDGE\s+(H-\d+)\s*:\s*(PASS|NEEDS_VALIDATION|DISCARD)", re.IGNORECASE)

VALIDATED = {"confirmed", "REPORTED", "ACCEPTED", "REJECTED"}
SUBMITTED = {"REPORTED", "ACCEPTED", "REJECTED"}


@dataclass
class Funnel:
    statuses: dict[str, str] = field(default_factory=dict)
    verdicts: dict[str, str] = field(default_factory=dict)

    @property
    def proposed(self) -> int:
        return len(self.statuses)

    @property
    def validated(self) -> int:
        # The judge only sees validated findings, so a judged-then-discarded finding still counts here.
        confirmed = {hid for hid, s in self.statuses.items() if s in VALIDATED}
        return len(confirmed | self.verdicts.keys())

    @property
    def passed(self) -> int:
        return sum(v == "PASS" for v in self.verdicts.values())

    @property
    def submitted(self) -> int:
        return sum(s in SUBMITTED for s in self.statuses.values())

    @property
    def accepted(self) -> int:
        return sum(s == "ACCEPTED" for s in self.statuses.values())

    def side_counts(self) -> Counter:
        return Counter(s for s in self.statuses.values() if s in {"rejected", "needs_validation", "DISCARDED"})


def parse(case_file: Path) -> Funnel:
    funnel = Funnel()
    for line in case_file.read_text(encoding="utf-8").splitlines():
        row = _ROW.match(line.strip())
        if row:
            cells = [c.strip() for c in row.group(2).split("|")]
            # Skip the template's placeholder row: an ID whose class column is still empty.
            if cells and cells[0]:
                funnel.statuses[row.group(1)] = cells[-1].split()[0] if cells[-1] else "candidate"
        for hid, verdict in _JUDGE.findall(line):
            funnel.verdicts[hid.upper()] = verdict.upper()
    return funnel


def render(funnel: Funnel, title: str) -> str:
    stages = [
        ("hypotheses proposed", funnel.proposed),
        ("validated", funnel.validated),
        ("passed the judge", funnel.passed),
        ("submitted", funnel.submitted),
        ("accepted", funnel.accepted),
    ]
    top = max(funnel.proposed, 1)
    width = 30
    lines = [f"Evidence funnel - {title}", ""]
    for label, count in stages:
        bar = "#" * max(round(width * count / top), 1 if count else 0)
        lines.append(f"  {label:<20} {count:>4}  {bar}")
    side = funnel.side_counts()
    if side:
        lines += ["", "  dropped: " + ", ".join(f"{k} {v}" for k, v in sorted(side.items()))]
    return "\n".join(lines)
