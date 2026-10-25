"""Check the local toolchain."""

from __future__ import annotations

import shutil
import subprocess
import sys

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
        out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    lines = (out.stdout or out.stderr).strip().splitlines()
    return lines[0][:60] if lines else ""


def run() -> int:
    missing_required = False
    print(f"  {'ok':<8} python {sys.version.split()[0]:<14} runs the bountyproof CLI")
    for cmd, required, why in TOOLS:
        path = shutil.which(cmd)
        if path:
            print(f"  {'ok':<8} {cmd:<21} {_version(cmd) or why}")
        else:
            missing_required |= required
            status = "MISSING" if required else "optional"
            print(f"  {status:<8} {cmd:<21} {why}")
    if shutil.which("claude"):
        listed = subprocess.run(["claude", "plugin", "list"], capture_output=True, text=True, timeout=60).stdout
        plugin = "ok" if "bountyproof" in listed else "optional"
        hint = "installed" if plugin == "ok" else "/plugin marketplace add jorge-asenjo/bountyproof"
        print(f"  {plugin:<8} {'bountyproof plugin':<21} {hint}")
    return 1 if missing_required else 0
