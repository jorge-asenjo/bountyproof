"""Check the local toolchain."""

from __future__ import annotations

import shutil
import subprocess
import sys

from bountyproof import profile

# (command, required, why)
TOOLS = [
    ("claude", True, "Claude Code runs the agents"),
    ("node", True, "runs the scope-guard hook"),
    ("git", True, "local history for each workspace"),
    ("docker", False, "white-box lab and the demo lab"),
    ("npx", False, "starts the Playwright MCP browser (black-box)"),
    ("gemini", False, "optional read-only discovery worker"),
    ("codex", False, "optional validation / threat-model worker"),
]


def _version(cmd: str) -> str:
    try:
        out = subprocess.run(
            [cmd, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    lines = (out.stdout or out.stderr).strip().splitlines()
    return lines[0][:60] if lines else ""


NODE_MIN = 18


def _node_major(version: str) -> int | None:
    """'v20.11.1' -> 20; None when the output isn't a Node version."""
    head = version.strip().lstrip("v").split(".", 1)[0]
    return int(head) if head.isdigit() else None


def _plugin_listed() -> bool | None:
    """True/False from `claude plugin list`; None when the call fails or hangs."""
    try:
        out = subprocess.run(
            ["claude", "plugin", "list"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return "bountyproof" in (out.stdout or "")


def run() -> int:
    missing_required = False
    print(f"  {'ok':<8} python {sys.version.split()[0]:<14} runs the bountyproof CLI")
    for cmd, required, why in TOOLS:
        path = shutil.which(cmd)
        if not path:
            missing_required |= required
            status = "MISSING" if required else "optional"
            print(f"  {status:<8} {cmd:<21} {why}")
            continue
        version = _version(cmd)
        if cmd == "node":
            major = _node_major(version)
            if major is not None and major < NODE_MIN:
                missing_required = True
                print(f"  {'OLD':<8} {cmd:<21} {version}: the scope guard needs Node.js {NODE_MIN}+")
                continue
        print(f"  {'ok':<8} {cmd:<21} {version or why}")
    if shutil.which("claude"):
        listed = _plugin_listed()
        if listed is None:
            print(f"  {'unknown':<8} {'bountyproof plugin':<21} `claude plugin list` didn't answer; check with /plugin")
        else:
            plugin = "ok" if listed else "optional"
            hint = "installed" if listed else "/plugin marketplace add jorge-asenjo/bountyproof"
            print(f"  {plugin:<8} {'bountyproof plugin':<21} {hint}")
    if profile.load() is None:
        print("\nNo hunter profile yet: run `bountyproof onboard` to set up accounts, devices and alerts.")
    return 1 if missing_required else 0
