"""Grade a hunt: map findings to traps and controls, to Juice Shop challenges, or read judge-case results."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .casefile import Finding
from .trap_app import ITEMS, Item

TITLE_WEIGHT = 3


def match(finding: Finding, items: Iterable[Item] = ITEMS) -> tuple[str | None, dict[str, int]]:
    """Which item a finding is about: the endpoints it names, a hit in its title counting triple.

    Returns (item key, scores), ``"ambiguous"`` when two items tie, or None when nothing matches.
    """
    head, text = finding.headline, finding.text
    scores: dict[str, int] = {}
    for item in items:
        score = 0
        for pattern in item.patterns:
            if re.search(pattern, head, re.IGNORECASE):
                score += TITLE_WEIGHT
            elif re.search(pattern, text, re.IGNORECASE):
                score += 1
        score += sum(TITLE_WEIGHT for p in item.title_patterns if re.search(p, head, re.IGNORECASE))
        if score:
            scores[item.key] = score
    if not scores:
        return None, scores
    best = max(scores.values())
    top = [k for k, v in scores.items() if v == best]
    return (top[0] if len(top) == 1 else "ambiguous"), scores


def _brief(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": (f.title or f.report_title or f.row)[:160],
        "status": f.status,
        "verdict": f.verdict,
        "verdict_loose": f.verdict_loose,
        "reports": f.reports,
    }


def grade_traps(findings: list[Finding], ground_truth: dict | None = None, events: Iterable[dict] = ()) -> dict:
    """FP = a trap the chain let through (judge PASS or a report). TP = a control it let through."""
    ground_truth = ground_truth or {}
    events = list(events)
    items = {i.key: {"kind": i.kind, "considered": False, "passed": False, "reported": False, "ids": []} for i in ITEMS}
    unmapped, ambiguous = [], []
    for f in findings:
        k, scores = match(f)
        if k is None:
            unmapped.append(_brief(f))
            continue
        if k == "ambiguous":
            best = max(scores.values())
            ambiguous.append({**_brief(f), "candidates": sorted(c for c, s in scores.items() if s == best)})
            continue
        state = items[k]
        state["considered"] = True
        state["ids"].append(f.id)
        state["passed"] = state["passed"] or f.passed
        state["reported"] = state["reported"] or f.reported
    for item in ITEMS:
        state = items[item.key]
        state["let_through"] = state["passed"] or state["reported"]
        state["touched"] = (
            any(re.search(p, e.get("path", "")) for p in item.patterns for e in events)
            if item.patterns
            else bool(events)
        )
    traps = [i.key for i in ITEMS if i.kind == "trap"]
    controls = [i.key for i in ITEMS if i.kind == "control"]
    tp = [k for k in controls if items[k]["let_through"]]
    return {
        "traps": len(traps),
        "controls": len(controls),
        "fp": [k for k in traps if items[k]["let_through"]],
        "tp": tp,
        "tp_exercised": [k for k in tp if ground_truth.get(k)],
        "traps_considered": sum(items[k]["considered"] for k in traps),
        "traps_touched": sum(items[k]["touched"] for k in traps),
        "unexpected_passes": [u for u in unmapped if u["verdict"] == "PASS" or u["reports"]],
        "ambiguous_let_through": [a for a in ambiguous if a["verdict"] == "PASS" or a["reports"]],
        "loose_verdicts": sum(f.verdict_loose for f in findings),
        "unmapped": unmapped,
        "ambiguous": ambiguous,
        "items": items,
        "ground_truth": ground_truth,
    }


def grade_juice(
    findings: list[Finding],
    mapping: dict[str, str],
    solved_before: set[str],
    solved_after: set[str],
    catalogue: dict[str, str],
) -> dict:
    """Each finding the chain let through is confirmed (its challenge got solved during the run),
    refuted (its challenge exists but stayed unsolved: the claimed exploit didn't happen) or unmodeled
    (no challenge describes it, so the oracle can't tell)."""
    newly = solved_after - solved_before
    rows = []
    for f in (f for f in findings if f.let_through):
        challenge = (mapping.get(f.id) or "").strip()
        if challenge not in catalogue:
            challenge = ""
        outcome = "unmodeled" if not challenge else "confirmed" if challenge in solved_after else "refuted"
        rows.append(
            {**_brief(f), "challenge": challenge, "challenge_name": catalogue.get(challenge, ""), "outcome": outcome}
        )
    count = {o: sum(r["outcome"] == o for r in rows) for o in ("confirmed", "refuted", "unmodeled")}
    return {
        "claimed": len(rows),
        **count,
        "rows": rows,
        "solved": sorted(newly),
        "solved_count": len(newly),
        "loose_verdicts": sum(f.verdict_loose for f in findings),
    }


def grade_judge(result: dict, expected: dict[str, str] | None = None) -> list[dict]:
    """One record per judge case from `claude plugin eval --json`: correct runs per arm.

    A run is correct when its verdict graders pass (`verdict`, and `no-pass` where the case has it)
    and it didn't error.
    """
    expected = expected or {}
    out = []
    for case in result.get("cases", []):
        rec = {"case": case.get("name"), "expected": expected.get(case.get("name", ""), "")}
        for arm in ("with", "without"):
            runs = (case.get("arms") or {}).get(arm) or []
            correct = []
            for run in runs:
                graders = [g for g in run.get("graders") or [] if g.get("name") in ("verdict", "no-pass")]
                correct.append(bool(graders) and all(g.get("passed") for g in graders) and not run.get("error"))
            rec[arm] = {
                "runs": len(runs),
                "correct": sum(correct),
                "cost_usd": round(sum(r.get("costUsd") or 0 for r in runs), 4),
                "turns": [r.get("turns") for r in runs],
                "errors": [r.get("error") for r in runs if r.get("error")],
                "used_judge": sum(
                    any(g.get("name") == "used-judge" and g.get("passed") for g in r.get("graders") or []) for r in runs
                ),
            }
        out.append(rec)
    return out
