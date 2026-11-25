"""Read what a hunt left in its workspace: one record per finding, from notes/case-file.md and reports/.

Statuses and judge verdicts come from ``bountyproof.funnel`` (the same parser `bountyproof funnel`
uses), so the eval counts exactly what the funnel shows.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from bountyproof import funnel  # noqa: E402

# A finding ID. The case file's own are H-001; hunts also write F-001 (finding), L-, C- or V-001.
_ID = re.compile(r"\b([HFLCV])-(\d+)([a-z]?)\b", re.IGNORECASE)
_ONE_ID = r"[HFLCV]-\d+[a-z]?"
_HEADING = re.compile(rf"^(#{{2,6}})\s*[*_`]*\s*({_ONE_ID}\b.*)$", re.IGNORECASE)
_TABLE_HEADER = re.compile(r"^\|\s*ID\s*\|(.*)\|\s*$", re.IGNORECASE)
_FIRST_CELL = re.compile(r"^\|([^|]*)\|")
_REPORT_TITLE = re.compile(r"^#\s+(.+)$", re.MULTILINE)
# A verdict written as prose ("Final: H-001 PASS + READY", "F-001, F-002: judge PASS") instead of
# `JUDGE H-001: PASS`. The IDs can't be part of a file name (reports/H-001-v2.md) and no other ID may sit
# between them and the verdict.
_LOOSE_VERDICT = re.compile(
    rf"\b({_ONE_ID}(?:\s*(?:,|/|&|\band\b)\s*{_ONE_ID})*)(?![\w./-])"
    rf"(?:(?!\b{_ONE_ID})[^|\n]){{0,40}}?\b(PASS|NEEDS_VALIDATION|DISCARD)\b"
)
_VERSION = re.compile(r"[-_. ]?v\d+$", re.IGNORECASE)  # reports/<name>-v2.md
_PLACEHOLDER_TITLE = re.compile(r"^<[^>]*>$")


def key(hid: str) -> str:
    """H-001, H-1 and h-001 are the same finding; F-001 is another one."""
    m = _ID.search(hid)
    return f"{m.group(1).upper()}-{int(m.group(2))}{m.group(3).lower()}" if m else hid


@dataclass
class Finding:
    id: str
    title: str = ""
    row: str = ""  # hypotheses-table row (class, shard, boundary): it names the bug like a title does
    body: str = ""
    status: str | None = None
    verdict: str | None = None
    verdict_loose: bool = False  # the verdict only exists as prose: `bountyproof funnel` can't see it
    reports: list[str] = field(default_factory=list)
    report_title: str = ""
    report_text: str = ""

    @property
    def passed(self) -> bool:
        return self.verdict == "PASS"

    @property
    def reported(self) -> bool:
        return bool(self.reports)

    @property
    def let_through(self) -> bool:
        """The chain's output: the judge passed it, or a report was written for it."""
        return self.passed or self.reported

    @property
    def headline(self) -> str:
        return " | ".join(x for x in (self.title, self.row, self.report_title) if x)

    @property
    def text(self) -> str:
        return "\n".join(x for x in (self.headline, self.body, self.report_text) if x)


def read(workspace: Path) -> tuple[list[Finding], funnel.Funnel]:
    case_file = workspace / "notes" / "case-file.md"
    if not case_file.is_file():
        return [], funnel.Funnel()
    text = case_file.read_text(encoding="utf-8", errors="replace")
    fun = funnel.parse(case_file)
    found: dict[str, Finding] = {}

    def get(hid: str) -> Finding:
        k = key(hid)
        if k not in found:
            found[k] = Finding(id=k)
        return found[k]

    for hid, status in fun.statuses.items():
        get(hid).status = status.rstrip(":;,.")  # "confirmed:" is confirmed
    for hid, verdict in fun.judged.items():  # verdicts on findings that reached the judge, as the funnel counts
        get(hid).verdict = verdict

    current: list[Finding] = []  # the dossier we're inside, if any
    status_table = False  # inside the hypotheses table (the one with a Status column)
    for raw in text.splitlines():
        line = raw.strip()
        heading = _HEADING.match(line)
        if heading:
            ids_part = re.split(r"\s[—–-]\s|:\s", heading.group(2), maxsplit=1)[0]
            current = [get(m.group(0)) for m in _ID.finditer(ids_part)]
            title = re.sub(r"^[\s+/&,:—–-]+", "", _ID.sub("", heading.group(2))).strip(" *_`")
            if _PLACEHOLDER_TITLE.match(title):  # the template's own "### H-001 — <title>"
                title = ""
            for f in current:
                f.title = f.title or title
            status_table = False
            continue
        if line.startswith("#"):
            current, status_table = [], False
            continue
        if line.startswith("|"):
            header = _TABLE_HEADER.match(line)
            if header:
                status_table = "status" in [c.strip().lower() for c in header.group(1).split("|")]
                continue
            first = _FIRST_CELL.match(line)
            ids = [m.group(0) for m in _ID.finditer(first.group(1))] if first else []
            cells = [c.strip() for c in line.strip("|").split("|")]
            if status_table and ids and len(cells) > 1 and not cells[1]:
                continue  # the template's placeholder row: no class, nothing proposed
            for hid in ids:
                f = get(hid)
                if status_table and not f.row:
                    f.row = line
                else:
                    f.body += line + "\n"
            if not ids:
                for f in current:
                    f.body += raw + "\n"
            continue
        status_table = False
        if current:
            for f in current:
                f.body += raw + "\n"
        else:
            for hid in {m.group(0) for m in _ID.finditer(line)}:
                get(hid).body += raw + "\n"

    # The judge's format is `JUDGE H-00X: VERDICT`. When a hunt writes it as prose instead, the last
    # prose verdict counts, for findings that reached the judge, and the finding is flagged.
    loose: dict[str, str] = {}
    for m in _LOOSE_VERDICT.finditer(text):
        for hid in _ID.finditer(m.group(1)):
            loose[key(hid.group(0))] = m.group(2)
    for k, verdict in loose.items():
        f = found.get(k)
        if f and f.verdict is None and f.status not in ("rejected", "needs_validation"):
            f.verdict, f.verdict_loose = verdict, True

    # The template's placeholder H-001 (no row, title, status, verdict or report) isn't a finding.
    for k in [k for k, f in found.items() if not (f.row or f.title or f.verdict or f.status or f.reports)]:
        found.pop(k)

    reports_dir = workspace / "reports"
    if reports_dir.is_dir():
        for path in sorted(reports_dir.glob("*.md")):
            # Every report counts, whatever its name: one without a finding ID is graded on its own text.
            m = _ID.search(path.name)
            f = get(m.group(0) if m else "report:" + _VERSION.sub("", path.stem))
            f.reports.append(path.name)
            content = path.read_text(encoding="utf-8", errors="replace")
            title = _REPORT_TITLE.search(content)
            if title and not f.report_title:
                f.report_title = title.group(1).strip()
            f.report_text += content[:6000] + "\n"

    return sorted(found.values(), key=_order), fun


def eval_funnel(findings: list[Finding], fun: funnel.Funnel) -> dict:
    """The funnel as it really went (statuses normalised, prose verdicts counted), next to what
    `bountyproof funnel` shows. A gap between the two means the hunt drifted from the case-file format."""
    return {
        "proposed": len(findings),
        "validated": sum(1 for f in findings if f.status in funnel.VALIDATED or f.verdict),
        "passed": sum(1 for f in findings if f.passed),
        "proposed_strict": fun.proposed,
        "validated_strict": fun.validated,
        "passed_strict": fun.passed,
    }


def _order(f: Finding) -> tuple[str, int, str]:
    m = _ID.fullmatch(f.id)
    return (m.group(1).upper(), int(m.group(2)), m.group(3)) if m else ("~", 10**9, f.id)
