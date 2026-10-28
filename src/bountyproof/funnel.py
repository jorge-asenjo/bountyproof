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

_ID = r"H-\d+[a-z]?"
_ROW = re.compile(rf"^\|\s*({_ID}(?:\s*\+\s*{_ID})*)\s*\|(.*)\|\s*$")
_HEADER = re.compile(r"^\|\s*ID\s*\|(.*)\|\s*$", re.IGNORECASE)
_JUDGE = re.compile(rf"JUDGE\s+({_ID})\s*:\s*(PASS|NEEDS_VALIDATION|DISCARD)", re.IGNORECASE)
_VERDICT = re.compile(r"PASS|NEEDS_VALIDATION|DISCARD", re.IGNORECASE)

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
    def judged(self) -> dict[str, str]:
        """Verdicts on hypotheses that reached the judge: known IDs, not rejected at validation."""
        return {
            hid: v
            for hid, v in self.verdicts.items()
            if not self.statuses or self.statuses.get(hid, "rejected") not in {"rejected", "needs_validation"}
        }

    @property
    def validated(self) -> int:
        # The judge only sees validated findings, so a judged-then-discarded finding still counts here.
        confirmed = {hid for hid, s in self.statuses.items() if s in VALIDATED}
        return len(confirmed | self.judged.keys())

    @property
    def passed(self) -> int:
        return sum(v == "PASS" for v in self.judged.values())

    @property
    def submitted(self) -> int:
        return sum(s in SUBMITTED for s in self.statuses.values())

    @property
    def accepted(self) -> int:
        return sum(s == "ACCEPTED" for s in self.statuses.values())

    def side_counts(self) -> Counter:
        dropped = {hid: s for hid, s in self.statuses.items() if s in {"rejected", "needs_validation", "DISCARDED"}}
        for hid, verdict in self.judged.items():
            if verdict == "DISCARD":
                dropped[hid] = "DISCARDED"
        return Counter(dropped.values())


def _status(cell: str) -> str:
    words = re.sub(r"[*`]", "", cell).split()
    return words[0] if words else "candidate"


def parse(case_file: Path) -> Funnel:
    """Read the hypotheses table (by its Status column) and the judge's verdicts (table or JUDGE lines)."""
    funnel = Funnel()
    status_col = verdict_col = None
    for line in case_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        header = _HEADER.match(line)
        if header:
            columns = [c.strip().lower() for c in header.group(1).split("|")]
            status_col = columns.index("status") if "status" in columns else None
            verdict_col = columns.index("verdict") if "verdict" in columns else None
            continue
        row = _ROW.match(line)
        if row:
            ids = [_norm(hid) for hid in re.findall(_ID, row.group(1))]
            cells = [c.strip() for c in row.group(2).split("|")]
            # A hypotheses row; the template's placeholder row has an empty class column.
            if status_col is not None and cells and cells[0]:
                cell = cells[status_col] if status_col < len(cells) else cells[-1]
                for hid in ids:
                    funnel.statuses[hid] = _status(cell)
            elif verdict_col is not None and verdict_col < len(cells):
                verdict = _VERDICT.match(re.sub(r"[*`]", "", cells[verdict_col]).strip())
                for hid in ids:
                    if verdict:
                        funnel.verdicts[hid] = verdict.group(0).upper()
        elif not line.startswith("|"):
            status_col = verdict_col = None  # the table ended
        for hid, verdict in _JUDGE.findall(line):
            funnel.verdicts[_norm(hid)] = verdict.upper()
    return funnel


def _norm(hid: str) -> str:
    return "H-" + hid[2:].lower()


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
