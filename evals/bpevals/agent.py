"""Run Claude Code headless for an eval: on the subscription (OAuth, never an API key), with only the
plugin under test, and nothing from the user's own setup (hooks, CLAUDE.md, skills, other plugins,
MCP servers, Claude in Chrome)."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Session variables of a parent Claude Code and API credentials never reach the eval.
_DROP = {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDECODE"}
_KEEP = {"CLAUDE_CODE_GIT_BASH_PATH", "CLAUDE_CODE_OAUTH_TOKEN"}


def clean_env(base: Mapping[str, str] | None = None, **extra: str) -> dict[str, str]:
    env = {
        k: v
        for k, v in (os.environ if base is None else base).items()
        if k.upper() in _KEEP or (k.upper() not in _DROP and not k.upper().startswith("CLAUDE_CODE_"))
    }
    env.update(extra)
    return env


def claude_bin() -> str:
    found = shutil.which("claude")
    if not found:
        raise SystemExit("Claude Code (`claude`) is not on PATH: https://code.claude.com")
    return found


def hunt_command(
    prompt: str,
    *,
    plugin_dir: Path,
    model: str,
    max_turns: int,
    mcp_config: Path | None = None,
    effort: str | None = None,
) -> list[str]:
    """`claude -p` for an unsupervised hunt. The workspace's own settings (its scope-guard hook) load;
    the user's don't. Permission prompts can't be answered, so anything that would ask is denied."""
    cmd = [
        claude_bin(),
        "-p",
        prompt,
        "--plugin-dir",
        str(plugin_dir),
        "--model",
        model,
        "--permission-mode",
        "bypassPermissions",
        "--permission-prompts",
        "none",
        "--setting-sources",
        "project,local",
        "--strict-mcp-config",
        "--no-chrome",
        "--disallowedTools",
        "WebFetch,WebSearch",
        "--max-turns",
        str(max_turns),
        "--no-session-persistence",
        "--output-format",
        "stream-json",
        "--verbose",
    ]
    if mcp_config:
        cmd += ["--mcp-config", str(mcp_config)]
    if effort:
        cmd += ["--effort", effort]
    return cmd


@dataclass
class AgentRun:
    exit_code: int | None = None
    timed_out: bool = False
    duration_s: float = 0.0
    subtype: str = ""  # from the result event: success, error_max_turns, ...
    is_error: bool | None = None
    num_turns: int | None = None
    cost_usd: float | None = None
    tokens_in: int = 0  # input + cache writes
    tokens_cache_read: int = 0
    tokens_out: int = 0
    models: dict = field(default_factory=dict)
    tool_uses: dict = field(default_factory=dict)
    subagents: int = 0
    subagent_types: dict = field(default_factory=dict)  # e.g. {"bountyproof:judge": 4}
    assistant_messages: dict = field(default_factory=dict)  # {"main": n, "subagents": n}
    plan_usage: dict = field(default_factory=dict)  # utilization of the plan's windows, first and last seen
    permission_denials: int = 0
    final_message: str = ""
    init_tools: list = field(default_factory=list)
    init_mcp: list = field(default_factory=list)
    init_plugins: list = field(default_factory=list)
    claude_version: str = ""
    error: str = ""

    @property
    def tokens_total(self) -> int:
        return self.tokens_in + self.tokens_cache_read + self.tokens_out

    def to_dict(self) -> dict:
        return {**asdict(self), "tokens_total": self.tokens_total}


def parse_stream(lines: Iterable[str]) -> AgentRun:
    """Read a `--output-format stream-json --verbose` transcript.

    A hunt that runs subagents in the background emits one ``result`` event each time the main loop
    goes idle and resumes. Usage and cost in them are cumulative, so the last one holds the totals;
    turns add up across them.
    """
    run = AgentRun()
    tools: Counter = Counter()
    messages: Counter = Counter()
    results: list[dict] = []
    windows: dict[str, list[float]] = {}
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        if kind == "system" and event.get("subtype") == "init":
            run.init_tools = sorted(event.get("tools") or [])
            run.init_mcp = [s.get("name") if isinstance(s, dict) else s for s in event.get("mcp_servers") or []]
            run.init_plugins = [p.get("name") if isinstance(p, dict) else p for p in event.get("plugins") or []]
            run.claude_version = str(event.get("claude_code_version") or "")
        elif kind == "assistant":
            messages["subagents" if event.get("parent_tool_use_id") else "main"] += 1
            for block in (event.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    tools[block.get("name", "?")] += 1
                elif isinstance(block, dict) and block.get("type") == "text" and not event.get("parent_tool_use_id"):
                    run.final_message = block.get("text") or run.final_message
        elif kind == "rate_limit_event":
            for name, window in ((event.get("rate_limit_info") or {}).get("unifiedWindows") or {}).items():
                if isinstance(window, dict) and isinstance(window.get("utilization"), (int, float)):
                    windows.setdefault(name, []).append(float(window["utilization"]))
        elif kind == "result":
            results.append(event)
    run.tool_uses = dict(tools.most_common())
    run.subagents = tools.get("Agent", 0) + tools.get("Task", 0)
    run.assistant_messages = dict(messages)
    run.plan_usage = {name: {"first": vals[0], "last": vals[-1]} for name, vals in windows.items()}
    if results:
        result = results[-1]
        stats = result.get("subagent_stats") or {}
        run.subagent_types = dict(stats.get("by_type") or {})
        run.subagents = max(run.subagents, int(stats.get("spawned") or 0))
        run.subtype = str(result.get("subtype") or "")
        run.is_error = result.get("is_error")
        run.num_turns = sum(int(r.get("num_turns") or 0) for r in results)
        run.cost_usd = max((r.get("total_cost_usd") or 0) for r in results)
        run.final_message = str(result.get("result") or run.final_message)
        run.permission_denials = sum(len(r.get("permission_denials") or []) for r in results)
        models = result.get("modelUsage") or {}
        run.models = {m: {k: v for k, v in u.items() if isinstance(v, (int, float))} for m, u in models.items()}
        if models:
            for usage in models.values():
                run.tokens_in += int(usage.get("inputTokens") or 0) + int(usage.get("cacheCreationInputTokens") or 0)
                run.tokens_cache_read += int(usage.get("cacheReadInputTokens") or 0)
                run.tokens_out += int(usage.get("outputTokens") or 0)
        else:
            usage = result.get("usage") or {}
            run.tokens_in = int(usage.get("input_tokens") or 0) + int(usage.get("cache_creation_input_tokens") or 0)
            run.tokens_cache_read = int(usage.get("cache_read_input_tokens") or 0)
            run.tokens_out = int(usage.get("output_tokens") or 0)
    else:
        run.error = "no result event (killed, timed out or crashed)"
    return run


def _kill_tree(proc: subprocess.Popen) -> None:
    """Claude Code starts children (MCP servers, a headless browser): stop all of them."""
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, check=False)
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()


def run(
    cmd: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_s: float,
    transcript: Path,
    stdin_text: str | None = None,
) -> AgentRun:
    """Run one session, streaming its transcript to ``transcript`` (stderr next to it)."""
    transcript.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = transcript.with_suffix(".stderr.txt")
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    start = time.monotonic()
    timed_out = False
    with transcript.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            encoding="utf-8",
            errors="replace",
            **kwargs,
        )
        try:
            if stdin_text is not None:
                proc.communicate(stdin_text, timeout=timeout_s)
            else:
                proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc)
    with transcript.open(encoding="utf-8", errors="replace") as handle:
        result = parse_stream(handle)
    result.exit_code = proc.returncode
    result.timed_out = timed_out
    result.duration_s = round(time.monotonic() - start, 1)
    if timed_out:
        result.error = f"timed out after {timeout_s:.0f}s"
    elif not result.error and proc.returncode:
        tail = stderr_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-3:]
        result.error = f"exit {proc.returncode}: " + " / ".join(tail)[:300]
    return result


def ask_json(prompt: str, schema: dict, *, model: str, cwd: Path, timeout_s: float = 300) -> dict | None:
    """One-shot structured answer (used to map Juice Shop findings to challenges). No tools, no settings."""
    cmd = [
        claude_bin(),
        "-p",
        "--model",
        model,
        "--tools",
        "",
        "--setting-sources",
        "project,local",
        "--strict-mcp-config",
        "--no-chrome",
        "--no-session-persistence",
        "--max-turns",
        "3",
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(schema),
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=prompt,
            cwd=cwd,
            env=clean_env(),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
        data = json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return None
    out = data.get("structured_output")
    if isinstance(out, dict):
        return out
    try:
        return json.loads(data.get("result") or "")
    except ValueError:
        return None
