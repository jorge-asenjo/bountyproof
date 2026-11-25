"""Summaries of a suite run, and the rows they add to evals/BASELINE.md."""

from __future__ import annotations

import statistics
from collections import Counter
from pathlib import Path


def _median(values: list) -> float | None:
    values = [v for v in values if isinstance(v, (int, float))]
    return statistics.median(values) if values else None


def _pct(n: int, d: int) -> str:
    return f"{n}/{d} ({n / d:.0%})" if d else "n/a"


def _tokens(n: float | None) -> str:
    if n is None:
        return "-"
    return f"{n / 1e6:.1f}M" if n >= 1e6 else f"{n / 1e3:.0f}k"


def _hunt_stats(ok: list[dict]) -> dict:
    agents = [r["agent"] for r in ok]
    return {
        "turns_median": _median([a.get("num_turns") for a in agents]),
        "tokens_in_median": _median([a.get("tokens_in") for a in agents]),
        "tokens_out_median": _median([a.get("tokens_out") for a in agents]),
        "tokens_cache_read_median": _median([a.get("tokens_cache_read") for a in agents]),
        "cost_usd_median": _median([a.get("cost_usd") for a in agents]),
        "minutes_median": _median([(a.get("duration_s") or 0) / 60 for a in agents]),
        "subagents_median": _median([a.get("subagents") for a in agents]),
        # Role separation: did the hunt hand discovery and validation to their own agents?
        "runs_spawning": {
            role: sum(1 for a in agents if (a.get("subagent_types") or {}).get(f"bountyproof:{role}"))
            for role in ("discoverer", "validator", "judge")
        },
        "plan_5h_used_median": _median(
            [round(w["last"] - w["first"], 3) for a in agents if (w := (a.get("plan_usage") or {}).get("five_hour"))]
        ),
        "funnel_median": {k: _median([r["funnel"][k] for r in ok]) for k in ("proposed", "validated", "passed")},
        "loose_verdicts": sum(r["grade"].get("loose_verdicts", 0) for r in ok if "grade" in r),
        "incomplete": [
            {"run": r["run"], "why": r["agent"].get("error") or r["agent"].get("subtype")}
            for r in ok
            if r["agent"].get("error") or r["agent"].get("subtype") not in ("", "success")
        ],
    }


def summarize(suite: str, records: list[dict]) -> dict:
    if suite == "judge":
        return _summarize_judge(records)
    ok = [r for r in records if "grade" in r]
    out = {
        "suite": suite,
        "runs": len(records),
        "runs_graded": len(ok),
        "errors": [r.get("error") for r in records if r.get("error")],
    }
    if not ok:
        return out
    out.update(_hunt_stats(ok))
    if suite == "traps":
        n_traps, n_controls = ok[0]["grade"]["traps"], ok[0]["grade"]["controls"]
        fp = sum(len(r["grade"]["fp"]) for r in ok)
        tp = sum(len(r["grade"]["tp"]) for r in ok)
        out.update(
            {
                "fp": fp,
                "fp_of": n_traps * len(ok),
                "tp": tp,
                "tp_of": n_controls * len(ok),
                "tp_exercised": sum(len(r["grade"]["tp_exercised"]) for r in ok),
                "fp_by_trap": dict(Counter(k for r in ok for k in r["grade"]["fp"]).most_common()),
                "tp_by_control": dict(Counter(k for r in ok for k in r["grade"]["tp"]).most_common()),
                "traps_considered_median": _median([r["grade"]["traps_considered"] for r in ok]),
                "traps_touched_median": _median([r["grade"]["traps_touched"] for r in ok]),
                "unexpected_passes": sum(len(r["grade"]["unexpected_passes"]) for r in ok),
                "ambiguous": sum(len(r["grade"]["ambiguous"]) for r in ok),
                "ambiguous_let_through": sum(len(r["grade"].get("ambiguous_let_through", [])) for r in ok),
                "touched_third_party": sum(bool(r["grade"]["ground_truth"].get("touched-third-party")) for r in ok),
            }
        )
    elif suite == "juice":
        out.update({k: sum(r["grade"][k] for r in ok) for k in ("claimed", "confirmed", "refuted", "unmodeled")})
        out["solved_median"] = _median([r["grade"]["solved_count"] for r in ok])
    return out


def _summarize_judge(records: list[dict]) -> dict:
    cases = [r["case"] for r in records if "case" in r]
    out = {"suite": "judge", "cases": len(cases), "errors": [r.get("error") for r in records if r.get("error")]}
    if not cases:
        return out
    for arm in ("with", "without"):
        runs = sum(c[arm]["runs"] for c in cases)
        correct = sum(c[arm]["correct"] for c in cases)
        out[arm] = {
            "runs": runs,
            "correct": correct,
            "cases_ok": sum(1 for c in cases if c[arm]["runs"] and c[arm]["correct"] == c[arm]["runs"]),
            "cost_usd": round(sum(c[arm]["cost_usd"] for c in cases), 2),
        }
    out["runs_per_arm"] = max((c["with"]["runs"] for c in cases), default=0)
    out["per_case"] = {
        c["case"]: f"{c['with']['correct']}/{c['with']['runs']} vs {c['without']['correct']}/{c['without']['runs']}"
        for c in cases
    }
    return out


# -------------------------------------------------------------------------------------- BASELINE.md

HEADINGS = {
    "traps": "## Traps",
    "juice": "## Juice Shop",
    "judge": "## Judge cases",
}


def row(suite: str, summary: dict, meta: dict) -> str:
    """One Markdown table row for evals/BASELINE.md."""
    plugin = meta.get("plugin") or {}
    ref = f"`{plugin.get('ref', '?')}` {str(plugin.get('commit', ''))[:7]}{'+' if plugin.get('dirty') else ''}"
    head = [meta.get("date", ""), meta.get("label", "") or "-", ref, f"`{meta.get('model', '')}`"]
    if suite == "judge":
        w, wo = summary.get("with", {}), summary.get("without", {})
        cells = head + [
            str(summary.get("runs_per_arm", "")),
            f"{w.get('cases_ok', 0)}/{summary.get('cases', 0)}",
            f"{w.get('correct', 0)}/{w.get('runs', 0)}",
            f"{wo.get('correct', 0)}/{wo.get('runs', 0)}",
            f"${w.get('cost_usd', 0):.2f}",
        ]
        return "| " + " | ".join(cells) + " |"
    fun = summary.get("funnel_median", {})
    funnel = " → ".join(_num(fun.get(k)) for k in ("proposed", "validated", "passed")) if fun else "-"
    tokens = (
        f"{_tokens(summary.get('tokens_in_median'))} / {_tokens(summary.get('tokens_out_median'))} / "
        f"{_tokens(summary.get('tokens_cache_read_median'))}"
    )
    common = [
        funnel,
        _num(summary.get("turns_median")),
        tokens,
        _num(summary.get("minutes_median")),
    ]
    runs = f"{summary.get('runs_graded', 0)}/{summary.get('runs', 0)}"
    if suite == "traps":
        cells = head + [
            runs,
            _pct(summary.get("fp", 0), summary.get("fp_of", 0)),
            _pct(summary.get("tp", 0), summary.get("tp_of", 0)),
        ]
    else:
        claimed = summary.get("claimed", 0)
        cells = head + [
            runs,
            str(claimed),
            _pct(summary.get("confirmed", 0), claimed),
            str(summary.get("refuted", 0)),
            str(summary.get("unmodeled", 0)),
            _num(summary.get("solved_median")),
        ]
    return "| " + " | ".join(cells + common) + " |"


def _num(v) -> str:
    if v is None:
        return "-"
    return f"{v:.0f}" if float(v).is_integer() or abs(v) >= 10 else f"{v:.1f}"


def append_row(baseline: Path, suite: str, line: str) -> None:
    """Add the row at the end of the suite's table (the table right under its heading)."""
    lines = baseline.read_text(encoding="utf-8").splitlines()
    start = next(i for i, text in enumerate(lines) if text.strip().startswith(HEADINGS[suite]))
    table = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("|"))
    end = table
    while end < len(lines) and lines[end].startswith("|"):
        end += 1
    lines.insert(end, line)
    baseline.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
