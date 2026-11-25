"""The three suites. Each run returns one JSON-ready record; evals/run.py writes and summarizes them.

- traps: the trap app (trap_app.py) hunted end to end by /bountyproof:hunt, unsupervised.
- juice: OWASP Juice Shop hunted the same way, its findings checked against the challenge oracle.
- judge: the judge cases under evals/judge-*, run by `claude plugin eval` with and without the plugin.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import agent, casefile, grade, juice, programs, trap_app, workspace

HUNT_PROMPT = "/bountyproof:hunt"  # neutral: the command a hunter types, nothing more
UA = "bountyproof-evals"
EVALS = Path(__file__).resolve().parents[1]


@dataclass
class Config:
    suite: str
    runs: int
    model: str
    out: Path
    plugin_ref: str | None = None
    max_turns: int = 400
    timeout_s: int = 5400
    parallel: int = 1
    browser: bool = True
    port: int = 0
    effort: str | None = None
    keep: bool = False
    label: str = ""
    classifier_model: str = "haiku"
    judge_arms: str = "both"  # "both" = with and without the plugin; "with" = with it only
    plugin_info: dict = field(default_factory=dict)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _base_record(cfg: Config, idx: int) -> dict:
    return {
        "suite": cfg.suite,
        "run": idx,
        "label": cfg.label,
        "started": _now(),
        "model": cfg.model,
        "effort": cfg.effort or "default",
        "plugin": cfg.plugin_info,
        "browser": cfg.browser,
    }


def _hunt(cfg: Config, plugin: Path, ws: Path, env: dict, run_dir: Path) -> agent.AgentRun:
    cmd = agent.hunt_command(
        HUNT_PROMPT,
        plugin_dir=plugin,
        model=cfg.model,
        max_turns=cfg.max_turns,
        mcp_config=ws / ".mcp.json" if cfg.browser else None,
        effort=cfg.effort,
    )
    return agent.run(cmd, cwd=ws, env=env, timeout_s=cfg.timeout_s, transcript=run_dir / "transcript.jsonl")


def _agent_fields(result: agent.AgentRun) -> dict:
    data = result.to_dict()
    final = data.pop("final_message", "")
    return {"agent": data, "final_message_tail": final[-1500:]}


def _found_fields(fun, findings: list) -> dict:
    return {
        "funnel": casefile.eval_funnel(findings, fun),
        "reports": sorted({name for f in findings for name in f.reports}),
    }


def _prepare(cfg: Config, plugin: Path, tmp: Path, name: str, files: dict, url: str, env: dict) -> Path:
    ws = workspace.create(plugin, tmp / "ws", name, env)
    workspace.write(ws, files)
    workspace.fill_claude_md(ws, [f"- {url} ({name}: the web app and its API)"])
    workspace.set_scope(ws, **programs.scope_fields(UA))
    workspace.confirm_scope(plugin, ws, env)
    checks = {
        "in_scope": workspace.check_scope(plugin, ws, url + "/", env),
        "other_host": workspace.check_scope(plugin, ws, "https://example.com/", env),
    }
    if checks != {"in_scope": "allow", "other_host": "deny"}:
        raise RuntimeError(f"scope guard not ready in the eval workspace: {checks}")
    return ws


# ------------------------------------------------------------------------------------------------ traps


def traps_run(cfg: Config, plugin: Path, idx: int) -> dict:
    rec = _base_record(cfg, idx)
    run_dir = cfg.out / f"run-{idx}"
    tmp = Path(tempfile.mkdtemp(prefix=f"bp-traps-{idx}-"))
    server, _ = trap_app.start(cfg.port + idx - 1 if cfg.port else 0)
    try:
        env = agent.clean_env(BOUNTYPROOF_HOME=str(tmp / "bp-home"))
        accounts = {k: (u.email, u.password) for k, u in server.state.accounts().items()}
        files = programs.traps_files(server.port, accounts, UA, cfg.browser)
        ws = _prepare(cfg, plugin, tmp, "Acme Board", files, server.base_url, env)
        result = _hunt(cfg, plugin, ws, env, run_dir)
        # Keep the hunt's output before grading it: if the grader breaks, --regrade can grade it later.
        rec.update(_agent_fields(result))
        rec["port"] = server.port
        rec["ground_truth"] = server.state.ground_truth()
        workspace.collect(ws, run_dir / "workspace")
        with (run_dir / "app-requests.jsonl").open("w", encoding="utf-8") as fh:
            for event in server.state.events:
                fh.write(json.dumps(event) + "\n")
        findings, fun = casefile.read(ws)
        rec["grade"] = grade.grade_traps(findings, rec["ground_truth"], server.state.events)
        rec.update(_found_fields(fun, findings))
    except Exception as exc:  # one broken run must not lose the others
        rec["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        server.shutdown()
        server.server_close()
        if not cfg.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            rec["workspace_tmp"] = str(tmp)
    rec["finished"] = _now()
    return rec


# ------------------------------------------------------------------------------------------------ juice

_docker_lock = threading.Lock()


def juice_run(cfg: Config, plugin: Path, idx: int) -> dict:
    rec = _base_record(cfg, idx)
    run_dir = cfg.out / f"run-{idx}"
    tmp = Path(tempfile.mkdtemp(prefix=f"bp-juice-{idx}-"))
    port = (cfg.port or juice.DEFAULT_PORT) + idx - 1
    name = f"{juice.CONTAINER}-{idx}"
    try:
        with _docker_lock:
            base = juice.start(port, name)
        accounts = {label: juice.register(base, label) for label in ("A", "B")}
        before = juice.challenges(base)
        env = agent.clean_env(BOUNTYPROOF_HOME=str(tmp / "bp-home"))
        files = programs.juice_files(port, accounts, UA, cfg.browser)
        ws = _prepare(cfg, plugin, tmp, "Juice Shop Lab", files, base, env)
        result = _hunt(cfg, plugin, ws, env, run_dir)
        rec.update(_agent_fields(result))  # as for traps: keep everything before grading
        rec["port"] = port
        after = juice.challenges(base)
        workspace.collect(ws, run_dir / "workspace")
        (run_dir / "oracle.json").write_text(
            json.dumps({"before": sorted(juice.solved(before)), "after": sorted(juice.solved(after))}, indent=2),
            encoding="utf-8",
        )
        (run_dir / "challenges.json").write_text(json.dumps(after), encoding="utf-8")
        findings, fun = casefile.read(ws)
        claimed = [f for f in findings if f.let_through]
        mapping = juice.map_findings(claimed, after, model=cfg.classifier_model, cwd=tmp)
        rec["grade"] = grade.grade_juice(
            findings, mapping, juice.solved(before), juice.solved(after), juice.catalogue(after)
        )
        rec.update(_found_fields(fun, findings))
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        juice.stop(name)
        if not cfg.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            rec["workspace_tmp"] = str(tmp)
    rec["finished"] = _now()
    return rec


def run_hunts(cfg: Config, plugin: Path, fn) -> list[dict]:
    with ThreadPoolExecutor(max_workers=max(cfg.parallel, 1)) as pool:
        return list(pool.map(lambda i: fn(cfg, plugin, i), range(1, cfg.runs + 1)))


def _jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def regrade(out: Path, records: list[dict], classifier_model: str = "haiku") -> list[dict]:
    """Grade saved hunts again from what each one left in its results folder, after a grader fix: no new
    hunt. Traps use run-N/workspace and app-requests.jsonl; juice also needs oracle.json and challenges.json."""
    for rec in records:
        run_dir = out / f"run-{rec['run']}"
        truth = rec.get("ground_truth") or rec.get("grade", {}).get("ground_truth")
        if "agent" not in rec or not (run_dir / "workspace").is_dir() or (rec["suite"] == "traps" and truth is None):
            continue  # the hunt itself didn't finish: nothing to grade
        findings, fun = casefile.read(run_dir / "workspace")
        rec.update(_found_fields(fun, findings))
        if rec["suite"] == "traps":
            events = _jsonl(run_dir / "app-requests.jsonl")
            rec["grade"] = grade.grade_traps(findings, truth, events)
        else:
            oracle = json.loads((run_dir / "oracle.json").read_text(encoding="utf-8"))
            chs = json.loads((run_dir / "challenges.json").read_text(encoding="utf-8"))
            claimed = [f for f in findings if f.let_through]
            with tempfile.TemporaryDirectory(prefix="bp-regrade-") as tmp:
                mapping = juice.map_findings(claimed, chs, model=classifier_model, cwd=Path(tmp))
            rec["grade"] = grade.grade_juice(
                findings, mapping, set(oracle["before"]), set(oracle["after"]), juice.catalogue(chs)
            )
        rec.pop("error", None)  # the hunt had finished: the error was the grader's, and it's graded now
        rec["regraded"] = _now()
    return records


# ------------------------------------------------------------------------------------------------ judge


def judge_cases() -> list[Path]:
    return sorted(p for p in EVALS.glob("judge-*") if (p / "case.yaml").is_file())


def _expected(case_dir: Path) -> str:
    for line in (case_dir / "case.yaml").read_text(encoding="utf-8").splitlines():
        if line.startswith("expected_outcome:"):
            return line.split(":", 1)[1].strip().strip("\"'")
    return ""


def judge_suite(cfg: Config, plugin: Path) -> list[dict]:
    """`claude plugin eval` on a clean snapshot, with this checkout's judge cases dropped into it."""
    cases = judge_cases()
    evals_dir = plugin / "evals"
    shutil.rmtree(evals_dir, ignore_errors=True)
    for case in cases:
        shutil.copytree(case, evals_dir / case.name)
    out_json = cfg.out / "plugin-eval.json"
    cmd = [
        agent.claude_bin(),
        "plugin",
        "eval",
        str(plugin),
        "--scaffold",
        "--trust-plugin",
        "--runs",
        str(cfg.runs),
        "--model",
        cfg.model,
        "--case",
        "judge-*",
        "--json",
        str(out_json),
        "--output-dir",
        str(cfg.out / "plugin-eval"),
        "--no-publish",
        "--concurrency",
        str(max(cfg.parallel, 1)),
    ]
    if cfg.judge_arms == "with":  # half the cost: no plugin-less baseline arm
        cmd += ["--ablation", "none"]
    started = _now()
    proc = subprocess.run(
        cmd,
        cwd=cfg.out,
        env=agent.clean_env(),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=cfg.timeout_s,
    )
    (cfg.out / "plugin-eval.log").write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
    if not out_json.is_file():
        return [{**_base_record(cfg, 0), "error": f"plugin eval wrote no JSON (exit {proc.returncode})"}]
    result = json.loads(out_json.read_text(encoding="utf-8"))
    expected = {case.name: _expected(case) for case in cases}
    records = []
    for case in grade.grade_judge(result, expected):
        rec = _base_record(cfg, 0)
        rec.update(
            {
                "started": started,
                "finished": _now(),
                "claude_version": result.get("claudeVersion", ""),
                "case": case,
            }
        )
        records.append(rec)
    return records
