"""Run one eval suite and record the numbers.

    python evals/run.py --suite traps --runs 3     # false positives of the whole chain (trap app)
    python evals/run.py --suite juice --runs 3     # honesty against the Juice Shop oracle (needs Docker)
    python evals/run.py --suite judge --runs 3     # the judge cases, with and without the plugin

Every hunt is `/bountyproof:hunt` run unsupervised by `claude -p` on your Claude subscription (never an
API key), with the model fixed and recorded. Raw results go to evals/results/<suite>/<timestamp>/
(gitignored); one summary row per suite run goes to evals/BASELINE.md. `--suite trampas` and
`--suite juez` work too.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bpevals import juice, report, suites, trap_app, workspace  # noqa: E402

EVALS = Path(__file__).resolve().parent
DEFAULT_MODEL = "claude-sonnet-5-5"
ALIASES = {"trampas": "traps", "juez": "judge"}
DEFAULTS = {  # max turns, timeout per run (s), port
    "traps": (400, 5400, trap_app.DEFAULT_PORT),
    "juice": (400, 9000, juice.DEFAULT_PORT),
    "judge": (0, 7200, 0),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evals/run.py", description=__doc__.splitlines()[0])
    p.add_argument("--suite", required=True, type=lambda s: ALIASES.get(s.lower(), s.lower()), choices=sorted(DEFAULTS))
    p.add_argument("--runs", type=int, default=3, help="runs per case (default 3, the minimum for a baseline)")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"model for every agent (default {DEFAULT_MODEL})")
    p.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], help="default: Claude Code's")
    p.add_argument("--plugin-ref", help="git ref of the plugin to test, e.g. main (default: the working tree)")
    p.add_argument("--parallel", type=int, default=1, help="runs at once (each hunt gets its own target)")
    p.add_argument("--max-turns", type=int, help="turn limit for the orchestrator of each hunt")
    p.add_argument("--timeout", type=int, help="seconds per hunt (judge: for the whole suite)")
    p.add_argument("--port", type=int, help="first target port (traps 8811, juice 3010)")
    p.add_argument("--no-browser", action="store_true", help="hunt with curl only (no Playwright MCP)")
    p.add_argument(
        "--arms",
        choices=["both", "with"],
        default="both",
        help="judge suite: with and without the plugin (default), or with it only (half the cost)",
    )
    p.add_argument("--label", default="", help="short note for the BASELINE.md row, e.g. 'main baseline'")
    p.add_argument("--keep", action="store_true", help="keep the temporary workspaces")
    p.add_argument("--no-baseline", action="store_true", help="don't add a row to evals/BASELINE.md")
    p.add_argument("--summarize", metavar="RUNS_JSONL", help="re-read a runs.jsonl and print (and record) its summary")
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    if args.runs < 1:
        raise SystemExit("--runs must be at least 1")
    if args.summarize:
        path = Path(args.summarize)
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return _finish(args, records, path.parent, records[0].get("plugin", {}) if records else {})

    turns, timeout, port = DEFAULTS[args.suite]
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = EVALS / "results" / args.suite / f"{stamp}-{args.model}"
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="bp-plugin-"))
    try:
        plugin = tmp / "plugin"
        info = workspace.snapshot(plugin, args.plugin_ref)
        cfg = suites.Config(
            suite=args.suite,
            runs=args.runs,
            model=args.model,
            out=out,
            plugin_ref=args.plugin_ref,
            max_turns=args.max_turns or turns,
            timeout_s=args.timeout or timeout,
            parallel=args.parallel,
            browser=not args.no_browser,
            port=args.port or port,
            effort=args.effort,
            keep=args.keep,
            label=args.label,
            judge_arms=args.arms,
            plugin_info=info,
        )
        print(f"== {args.suite}: {args.runs} run(s), model {args.model}, plugin {info['ref']} {info['commit'][:7]}")
        print(f"   results: {out}")
        if args.suite == "judge":
            records = suites.judge_suite(cfg, plugin)
        else:
            fn = suites.traps_run if args.suite == "traps" else suites.juice_run
            records = suites.run_hunts(cfg, plugin, fn)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    with (out / "runs.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    return _finish(args, records, out, info)


def _finish(args, records: list[dict], out: Path, info: dict) -> int:
    summary = report.summarize(args.suite, records)
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    meta = {
        "date": (records[0].get("started", "") if records else "")[:10],
        "label": args.label,
        "plugin": info,
        "model": records[0].get("model", args.model) if records else args.model,
    }
    line = report.row(args.suite, summary, meta)
    print("\n" + line)
    if not args.no_baseline:
        report.append_row(EVALS / "BASELINE.md", args.suite, line)
        print("   added to evals/BASELINE.md")
    return 1 if summary.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
