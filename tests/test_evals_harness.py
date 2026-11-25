"""The eval runner and its grading, offline: no model, no network, no Docker."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import needs_node

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evals"))

import run as eval_run  # noqa: E402
from bpevals import agent, casefile, grade, programs, report, suites, trap_app, workspace  # noqa: E402

CASE_FILE = """# Case File

## 2. Hypotheses (the work queue)

| ID | Class | Shard / artifact | Trust boundary | Confidence | Status |
|----|-------|------------------|----------------|------------|--------|
| H-001 | | | | low/med/high | candidate |
| H-001 | idor | GET /api/invoices/{id} | A -> B | high | confirmed: A reads B's invoice |
| H-002 | xss | POST /api/comments -> /board | A -> B | high | **confirmed** |
| H-003 | idor | GET /api/orders/{id} | A -> B | med | confirmed |
| H-004 | cors | GET /api/catalog | origin | low | rejected: public data |
| H-005 | ssrf | POST /api/import, GET /preview | egress | med | needs_validation |
| H-006 | logic | password reset | anon | low | confirmed |

## 3. Evidence dossiers

### H-001 — <title>
- **Affected asset / trust boundary:**

### H-003 — Order IDOR on GET /api/orders/{id}
- A requests 7002 and gets {"order": 7002, "ok": true}. Server: Apache/2.2.8 (Unix)

### H-006 — Reset token reuse
- Unclear.

## 6. Judge
JUDGE H-003: PASS
JUDGE H-004: PASS
JUDGE H-006: DISCARD (no impact)

### Final: H-001 PASS + READY (reports/H-001-v2.md). H-002 NEEDS_VALIDATION, then H-002 PASS + READY.
"""


def make_workspace(root: Path) -> Path:
    ws = root / "ws"
    (ws / "notes").mkdir(parents=True)
    (ws / "reports").mkdir()
    (ws / "notes" / "case-file.md").write_text(CASE_FILE, encoding="utf-8")
    (ws / "reports" / "H-001-v2.md").write_text("# IDOR on /api/invoices exposes other customers' invoices\n")
    return ws


# ------------------------------------------------------------------------------------------ casefile


def test_casefile_reads_statuses_verdicts_and_reports(tmp_path):
    findings, fun = casefile.read(make_workspace(tmp_path))
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {"H-1", "H-2", "H-3", "H-4", "H-5", "H-6"}
    assert by_id["H-1"].status == "confirmed" and by_id["H-1"].verdict == "PASS" and by_id["H-1"].verdict_loose
    assert by_id["H-1"].title == ""  # the template placeholder title is ignored
    assert "/api/invoices" in by_id["H-1"].row and by_id["H-1"].reports == ["H-001-v2.md"]
    assert by_id["H-2"].verdict == "PASS" and by_id["H-2"].verdict_loose  # the last prose verdict wins
    assert by_id["H-3"].verdict == "PASS" and not by_id["H-3"].verdict_loose
    assert by_id["H-4"].verdict is None  # rejected at validation: the judge line doesn't count
    assert "Apache/2.2.8" in by_id["H-3"].body
    funnel = casefile.eval_funnel(findings, fun)
    assert funnel == {
        "proposed": 6,
        "validated": 4,
        "passed": 3,
        "proposed_strict": 6,
        "validated_strict": 4,
        "passed_strict": 1,
    }


def test_casefile_without_case_file(tmp_path):
    assert casefile.read(tmp_path)[0] == []


# A hunt that left the hypotheses table as the template had it and logged its findings as F-001...
HUNT_LOG_CASE_FILE = """# Case File

## 2. Hypotheses (the work queue)

| ID | Class | Shard / artifact | Trust boundary | Confidence | Status |
|----|-------|------------------|----------------|------------|--------|
| H-001 | | | | low/med/high | candidate |

## 3. Evidence dossiers (one per hypothesis)

### H-001 — <title>
- **Affected asset / trust boundary:**

## HUNT LOG 2026-11-25

### F-001 IDOR: GET /api/invoices/{id} (CONFIRMED)
- A reads B's invoice 5002.

### F-002 SSRF: POST /api/import {url} (CONFIRMED)
- The importer returns /internal/metadata.

### Review status
F-001, F-002: judge PASS; review READY. Reports: reports/F-00{1,2}-v2.md
"""


def make_hunt_log_workspace(root: Path) -> Path:
    ws = root / "ws"
    (ws / "notes").mkdir(parents=True)
    (ws / "reports").mkdir()
    (ws / "notes" / "case-file.md").write_text(HUNT_LOG_CASE_FILE, encoding="utf-8")
    (ws / "reports" / "F-001-v2.md").write_text("# IDOR on /api/invoices\n", encoding="utf-8")
    (ws / "reports" / "F-002-v2.md").write_text("# SSRF in the importer\n", encoding="utf-8")
    (ws / "reports" / "comments-xss-v1.md").write_text("# Stored XSS in /api/comments\n", encoding="utf-8")
    return ws


def test_casefile_reads_other_prefixes_and_every_report(tmp_path):
    findings, fun = casefile.read(make_hunt_log_workspace(tmp_path))
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {"F-1", "F-2", "report:comments-xss"}  # the template's H-001 isn't a finding
    assert by_id["F-1"].verdict == "PASS" and by_id["F-1"].verdict_loose  # "F-001, F-002: judge PASS"
    assert by_id["F-2"].verdict == "PASS" and by_id["F-1"].reports == ["F-001-v2.md"]
    assert by_id["report:comments-xss"].reported  # a report without an ID still counts
    assert casefile.key("F-001") == "F-1" != casefile.key("H-001")
    funnel = casefile.eval_funnel(findings, fun)
    assert (funnel["proposed"], funnel["passed"], funnel["proposed_strict"], funnel["passed_strict"]) == (3, 2, 0, 0)
    truth = {"control/idor-invoices": True, "control/ssrf-internal": True, "control/stored-xss-comments": False}
    g = grade.grade_traps(findings, truth, [])
    assert g["tp"] == ["control/idor-invoices", "control/stored-xss-comments", "control/ssrf-internal"]


# --------------------------------------------------------------------------------------------- grade


def test_match_prefers_the_title_and_flags_ties(tmp_path):
    findings = {f.id: f for f in casefile.read(make_workspace(tmp_path))[0]}
    assert grade.match(findings["H-1"])[0] == "control/idor-invoices"
    assert grade.match(findings["H-2"])[0] == "control/stored-xss-comments"
    assert grade.match(findings["H-3"])[0] == "trap/reachable-no-data"  # the banner in the body doesn't count
    assert grade.match(findings["H-5"])[0] == "ambiguous"
    assert grade.match(findings["H-6"])[0] is None


def test_grade_traps(tmp_path):
    findings = casefile.read(make_workspace(tmp_path))[0]
    truth = {"control/idor-invoices": True, "control/stored-xss-comments": False}
    events = [{"path": "/api/orders/7002"}, {"path": "/search"}]
    g = grade.grade_traps(findings, truth, events)
    assert g["fp"] == ["trap/reachable-no-data"]  # H-003 passed the judge on a trap
    assert g["tp"] == ["control/idor-invoices", "control/stored-xss-comments"]
    assert g["tp_exercised"] == ["control/idor-invoices"]  # the XSS was claimed but never stored
    assert "trap/cors-reflected-public" not in g["fp"]  # rejected before the judge
    assert g["loose_verdicts"] == 2 and len(g["ambiguous"]) == 1 and g["ambiguous_let_through"] == []
    assert g["items"]["trap/xss-escaped"]["touched"] and not g["items"]["trap/sqli-canned"]["touched"]
    assert g["items"]["trap/version-banner"]["touched"]  # every response carries the banner
    assert g["unexpected_passes"] == []


def test_grade_juice_outcomes():
    findings = [
        casefile.Finding(id="H-1", title="Login SQLi as admin", verdict="PASS"),
        casefile.Finding(id="H-2", title="View another basket", verdict="PASS"),
        casefile.Finding(id="H-3", title="Something unmodeled", reports=["H-3-v2.md"]),
        casefile.Finding(id="H-4", title="Never passed", verdict="DISCARD"),
    ]
    mapping = {"H-1": "loginAdminChallenge", "H-2": "viewBasketChallenge", "H-3": "", "H-4": "x"}
    catalogue = {"loginAdminChallenge": "Login Admin", "viewBasketChallenge": "View Basket"}
    g = grade.grade_juice(findings, mapping, set(), {"loginAdminChallenge", "scoreBoardChallenge"}, catalogue)
    assert (g["claimed"], g["confirmed"], g["refuted"], g["unmodeled"]) == (3, 1, 1, 1)
    assert g["solved_count"] == 2


def test_grade_judge():
    result = {
        "cases": [
            {
                "name": "judge-x",
                "arms": {
                    "with": [
                        {"graders": [{"name": "verdict", "passed": True}, {"name": "used-judge", "passed": True}]},
                        {"graders": [{"name": "verdict", "passed": True}, {"name": "no-pass", "passed": False}]},
                    ],
                    "without": [{"graders": [{"name": "verdict", "passed": True}], "error": "timeout"}],
                },
            }
        ]
    }
    (case,) = grade.grade_judge(result, {"judge-x": "reject"})
    assert case["with"]["correct"] == 1 and case["with"]["used_judge"] == 1
    assert case["without"]["correct"] == 0 and case["without"]["errors"] == ["timeout"]


# --------------------------------------------------------------------------------------------- agent


def test_clean_env_drops_keys_and_parent_session():
    env = agent.clean_env(
        {
            "PATH": "x",
            "ANTHROPIC_API_KEY": "sk",
            "CLAUDECODE": "1",
            "CLAUDE_CODE_SESSION_ID": "s",
            "CLAUDE_CODE_GIT_BASH_PATH": "bash",
            "CLAUDE_CODE_OAUTH_TOKEN": "t",
        },
        BOUNTYPROOF_HOME="h",
    )
    assert env == {
        "PATH": "x",
        "CLAUDE_CODE_GIT_BASH_PATH": "bash",
        "CLAUDE_CODE_OAUTH_TOKEN": "t",
        "BOUNTYPROOF_HOME": "h",
    }


def test_hunt_command_isolates_the_session(monkeypatch, tmp_path):
    monkeypatch.setattr(agent.shutil, "which", lambda name: "claude")
    cmd = agent.hunt_command(
        "/bountyproof:hunt", plugin_dir=tmp_path, model="m", max_turns=9, mcp_config=tmp_path / "m.json"
    )
    assert cmd[:3] == ["claude", "-p", "/bountyproof:hunt"]
    joined = " ".join(cmd)
    for flag in ("--setting-sources project,local", "--strict-mcp-config", "--no-chrome", "--permission-prompts none"):
        assert flag in joined
    assert "WebFetch,WebSearch" in cmd and cmd[cmd.index("--model") + 1] == "m"


def test_parse_stream_sums_background_turns():
    lines = [
        {"type": "system", "subtype": "init", "tools": ["Bash", "Read"], "mcp_servers": [{"name": "playwright"}]},
        {"type": "rate_limit_event", "rate_limit_info": {"unifiedWindows": {"five_hour": {"utilization": 0.4}}}},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Agent"}]}},
        {
            "type": "assistant",
            "parent_tool_use_id": "t1",
            "message": {"content": [{"type": "tool_use", "name": "Bash"}]},
        },
        {"type": "result", "num_turns": 10, "total_cost_usd": 0.5, "subtype": "success"},
        {"type": "rate_limit_event", "rate_limit_info": {"unifiedWindows": {"five_hour": {"utilization": 0.45}}}},
        {
            "type": "result",
            "num_turns": 3,
            "total_cost_usd": 0.7,
            "subtype": "success",
            "result": "done",
            "subagent_stats": {"spawned": 2, "by_type": {"bountyproof:judge": 2}},
            "modelUsage": {
                "m": {"inputTokens": 5, "cacheCreationInputTokens": 5, "cacheReadInputTokens": 100, "outputTokens": 7}
            },
        },
    ]
    run = agent.parse_stream(json.dumps(x) for x in lines)
    assert run.num_turns == 13 and run.cost_usd == 0.7 and run.final_message == "done"
    assert (run.tokens_in, run.tokens_cache_read, run.tokens_out) == (10, 100, 7)
    assert run.subagents == 2 and run.subagent_types == {"bountyproof:judge": 2}
    assert run.assistant_messages == {"main": 1, "subagents": 1}
    assert run.plan_usage == {"five_hour": {"first": 0.4, "last": 0.45}}
    assert run.init_mcp == ["playwright"] and not run.error


def test_parse_stream_without_result():
    assert agent.parse_stream(["not json", ""]).error


# ----------------------------------------------------------------------------------------- workspace


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_snapshot_ref_and_worktree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / ".gitignore").write_text(".venv/\n")
    (repo / "a.txt").write_text("v1")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "one")
    (repo / "a.txt").write_text("v2")
    (repo / "new.txt").write_text("untracked")
    (repo / ".venv").mkdir()
    (repo / ".venv" / "x").write_text("ignored")
    at_ref = workspace.snapshot(tmp_path / "ref", "HEAD", repo)
    assert (tmp_path / "ref" / "a.txt").read_text() == "v1" and not (tmp_path / "ref" / "new.txt").exists()
    assert at_ref["dirty"] is False and len(at_ref["commit"]) == 40
    tree = workspace.snapshot(tmp_path / "tree", None, repo)
    assert (tmp_path / "tree" / "a.txt").read_text() == "v2" and (tmp_path / "tree" / "new.txt").exists()
    assert not (tmp_path / "tree" / ".venv").exists() and tree["dirty"] is True


@needs_node
def test_eval_workspace_is_ready_to_hunt(tmp_path):
    """The harness builds the workspace with the plugin's own CLI and confirms the scope it wrote."""
    plugin = ROOT
    env = agent.clean_env(BOUNTYPROOF_HOME=str(tmp_path / "home"))
    cfg = suites.Config(suite="traps", runs=1, model="m", out=tmp_path / "out")
    accounts = {"A": ("a@acme-board.test", "pa"), "B": ("b@acme-board.test", "pb")}
    files = programs.traps_files(8811, accounts, suites.UA, browser=True)
    ws = suites._prepare(cfg, plugin, tmp_path, "Acme Board", files, "http://127.0.0.1:8811", env)
    scope = json.loads((ws / "notes" / "scope.json").read_text(encoding="utf-8"))
    assert scope["requireConfirm"] is True and scope["confirmedScope"] and scope["uaTag"] == "bountyproof-evals"
    assert "Fill with Claude in Chrome: off" in (ws / "notes" / "hunter-profile.md").read_text(encoding="utf-8")
    assert "http://127.0.0.1:8811" in (ws / "CLAUDE.md").read_text(encoding="utf-8")
    assert "pb" in (ws / "notes" / "accounts.md").read_text(encoding="utf-8")
    mcp = json.loads((ws / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["playwright"]["args"]
    assert programs.PLAYWRIGHT_MCP in mcp and "--headless" in mcp and "--isolated" in mcp
    out = tmp_path / "collected"
    workspace.collect(ws, out)
    assert (out / "notes" / "case-file.md").is_file() and not (out / "notes" / "accounts.md").exists()


def test_juice_rules_follow_the_lab():
    files = programs.juice_files(3010, {"A": ("a", "1"), "B": ("b", "2")}, "ua-x", browser=False)
    rules = files["notes/program-rules.md"]
    assert "http://localhost:3010" in rules and "`ua-x`" in rules and "localhost:3000" not in rules
    assert ".mcp.json" not in files


# -------------------------------------------------------------------------------------------- report


def _record(run, fp, tp, error=None):
    rec = {
        "run": run,
        "started": "2026-11-25T10:00:00+00:00",
        "model": "m",
        "plugin": {"ref": "main", "commit": "abcdef0123", "dirty": False},
    }
    if error:
        return {**rec, "error": error}
    return {
        **rec,
        "agent": {
            "num_turns": 40,
            "tokens_in": 120_000,
            "tokens_out": 30_000,
            "tokens_cache_read": 1_500_000,
            "cost_usd": 0.9,
            "duration_s": 300,
            "subagents": 4,
            "subagent_types": {"bountyproof:judge": 4},
            "plan_usage": {"five_hour": {"first": 0.4, "last": 0.5}},
            "subtype": "success",
        },
        "funnel": {"proposed": 7, "validated": 2, "passed": 2},
        "grade": {
            "traps": 16,
            "controls": 4,
            "fp": fp,
            "tp": tp,
            "tp_exercised": tp,
            "traps_considered": 3,
            "traps_touched": 13,
            "unexpected_passes": [],
            "ambiguous": [],
            "ground_truth": {},
            "loose_verdicts": 2,
        },
    }


def test_summarize_and_baseline_row(tmp_path):
    records = [_record(1, [], ["control/idor-invoices"]), _record(2, ["trap/self-xss"], []), _record(3, [], [], "boom")]
    summary = report.summarize("traps", records)
    assert (summary["fp"], summary["fp_of"], summary["tp"], summary["tp_of"]) == (1, 32, 1, 8)
    assert summary["runs_spawning"] == {"discoverer": 0, "validator": 0, "judge": 2}
    assert summary["errors"] == ["boom"] and summary["plan_5h_used_median"] == 0.1
    line = report.row(
        "traps", summary, {"date": "2026-11-25", "label": "main baseline", "plugin": records[0]["plugin"], "model": "m"}
    )
    assert line.startswith(
        "| 2026-11-25 | main baseline | `main` abcdef0 | `m` | 2/3 | 1/32 (3%) | 1/8 (12%) | 7 → 2 → 2 |"
    )
    baseline = tmp_path / "BASELINE.md"
    shutil.copy(ROOT / "evals" / "BASELINE.md", baseline)
    report.append_row(baseline, "traps", line)
    report.append_row(baseline, "traps", line.replace("main baseline", "second"))
    text = baseline.read_text(encoding="utf-8")
    assert text.index("main baseline") < text.index("second") < text.index("## Juice Shop")


def test_columns_match_the_baseline_tables():
    text = (ROOT / "evals" / "BASELINE.md").read_text(encoding="utf-8")
    meta = {"date": "d", "label": "l", "plugin": {}, "model": "m"}
    for suite, heading in report.HEADINGS.items():
        header = next(line for line in text.split(heading, 1)[1].splitlines() if line.startswith("|"))
        summary = {"suite": suite} if suite != "judge" else {"cases": 0}
        assert report.row(suite, summary, meta).count("|") == header.count("|"), suite


def test_run_py_aliases_and_summarize(tmp_path, capsys):
    parser = eval_run.build_parser()
    assert parser.parse_args(["--suite", "trampas"]).suite == "traps"
    assert parser.parse_args(["--suite", "juez"]).suite == "judge"
    runs = tmp_path / "runs.jsonl"
    runs.write_text("\n".join(json.dumps(r) for r in [_record(1, [], ["control/race-coupon"])]), encoding="utf-8")
    assert eval_run.main(["--suite", "traps", "--summarize", str(runs), "--no-baseline"]) == 0
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))["tp"] == 1
    assert "1/4 (25%)" in capsys.readouterr().out


def test_regrade_reads_the_saved_runs_again(tmp_path, capsys):
    out = tmp_path / "results"
    shutil.copytree(make_hunt_log_workspace(tmp_path), out / "run-1" / "workspace")
    (out / "run-1" / "app-requests.jsonl").write_text(json.dumps({"path": "/api/invoices/5002"}) + "\n")
    old = {**_record(1, [], []), "suite": "traps", "label": "main baseline"}  # graded before: nothing found
    old["grade"]["ground_truth"] = {"control/idor-invoices": True, "control/ssrf-internal": True}
    (out / "runs.jsonl").write_text(json.dumps(old) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        eval_run.main(["--suite", "juice", "--regrade", str(out), "--no-baseline"])
    assert eval_run.main(["--suite", "traps", "--regrade", str(out), "--no-baseline"]) == 0
    rec = json.loads((out / "runs.jsonl").read_text(encoding="utf-8"))
    assert rec["grade"]["tp"] == ["control/idor-invoices", "control/stored-xss-comments", "control/ssrf-internal"]
    assert rec["grade"]["tp_exercised"] == ["control/idor-invoices", "control/ssrf-internal"]
    assert rec["funnel"]["proposed"] == 3 and "regraded" in rec
    assert (out / "runs.before-regrade.jsonl").is_file()
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["tp"] == 3 and summary["funnel_strict_median"]["passed"] == 0
    assert "| main baseline |" in capsys.readouterr().out  # the label comes from the saved runs


def test_trap_items_cover_the_plan():
    keys = {i.key for i in trap_app.ITEMS}
    for needed in (
        "trap/reachable-no-data",
        "trap/layer-order",
        "trap/own-data-only",
        "trap/open-redirect-unchained",
        "trap/self-xss",
        "trap/cors-reflected-public",
        "trap/already-obtainable",
        "trap/insider-precondition",
        "control/idor-invoices",
        "control/stored-xss-comments",
        "control/ssrf-internal",
        "control/race-coupon",
    ):
        assert needed in keys
