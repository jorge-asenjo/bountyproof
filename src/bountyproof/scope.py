"""Scope confirmation and dry-run checks against the scope-guard hook.

The confirmation hash must match ``hooks/scope-guard.mjs`` byte for byte: the three scope lists,
each trimmed, lowercased, de-duplicated and ordinal-sorted, joined, then SHA-256 hex.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from bountyproof.assets import hook_path

SCOPE_LISTS = ("inScope", "outOfScope", "denyUnlisted")


class ScopeError(RuntimeError):
    pass


def load(scope_file: Path) -> dict:
    try:
        return json.loads(scope_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScopeError(f"{scope_file} not found. Run this from an engagement workspace.") from None
    except json.JSONDecodeError as exc:
        raise ScopeError(f"{scope_file} is not valid JSON: {exc}") from None


def _canon(values: object) -> str:
    items = values if isinstance(values, list) else []
    unique = {str(v).strip().lower() for v in items if str(v).strip()}
    return ",".join(sorted(unique))


def scope_hash(scope: dict) -> str:
    canon = "|".join(f"{key}={_canon(scope.get(key))}" for key in SCOPE_LISTS)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def confirm(scope_file: Path, scope: dict) -> str:
    digest = scope_hash(scope)
    scope["confirmedScope"] = digest
    scope_file.write_text(json.dumps(scope, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return digest


@dataclass(frozen=True)
class Verdict:
    decision: str  # allow | ask | deny | inactive
    reason: str = ""


def check(workspace: Path, target: str, ua: str | None = None) -> Verdict:
    """Ask the hook what it would do with a request, without sending anything.

    ``target`` is a URL (checked as a curl GET carrying the program's UA tag) or a full shell command.
    """
    scope = load(workspace / "notes" / "scope.json")
    if scope.get("enforce") is False or not scope.get("inScope"):
        return Verdict("inactive", "notes/scope.json has no inScope entries yet, so the guard is off.")

    if " " in target.strip():
        command = target
    else:
        tag = ua if ua is not None else str(scope.get("uaTag") or "")
        command = f"curl -A {shlex.quote(('Mozilla/5.0 ' + tag).strip())} {shlex.quote(target)}"

    node = shutil.which("node")
    if node is None:
        raise ScopeError("Node.js is required to run the scope guard (https://nodejs.org).")

    local = workspace / ".claude" / "hooks" / "scope-guard.mjs"
    hook = local if local.is_file() else hook_path()
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(workspace), "BOUNTYPROOF_DRY_RUN": "1"}
    proc = subprocess.run([node, str(hook)], input=payload, capture_output=True, encoding="utf-8", env=env, timeout=30)
    if not proc.stdout.strip():
        return Verdict("allow")
    out = json.loads(proc.stdout).get("hookSpecificOutput", {})
    return Verdict(out.get("permissionDecision", "allow"), out.get("permissionDecisionReason", ""))
