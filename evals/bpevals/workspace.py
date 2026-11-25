"""The plugin under test and the engagement workspace each eval run hunts in.

The plugin is a snapshot: a git ref (``--plugin-ref main``) or the working tree. Workspaces are made
by that snapshot's own CLI, so a run measures one version of the template, prompts, agents and hook.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _git(*args: str, cwd: Path = REPO) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)
    return proc.stdout.decode("utf-8", "replace")


def snapshot(dest: Path, ref: str | None = None, repo: Path = REPO) -> dict:
    """Copy the plugin at ``ref`` (or the working tree: tracked and untracked files, nothing ignored)
    into ``dest``. A clean copy also keeps `claude plugin eval` away from a local `.venv`."""
    dest.mkdir(parents=True, exist_ok=True)
    if ref:
        commit = _git("rev-parse", "--verify", f"{ref}^{{commit}}", cwd=repo).strip()
        data = subprocess.run(["git", "archive", "--format=tar", commit], cwd=repo, capture_output=True, check=True)
        with tarfile.open(fileobj=io.BytesIO(data.stdout)) as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(dest, filter="data")
            else:  # pragma: no cover - old Python without extraction filters
                tar.extractall(dest)  # noqa: S202 - our own git archive
        return {"ref": ref, "commit": commit, "dirty": False}
    listed = _git("ls-files", "-z", "--cached", "--others", "--exclude-standard", cwd=repo).split("\0")
    for rel in filter(None, listed):
        src = repo / rel
        if src.is_file():
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
    commit = _git("rev-parse", "HEAD", cwd=repo).strip()
    dirty = bool(_git("status", "--porcelain", "--untracked-files=no", cwd=repo).strip())
    return {"ref": "worktree", "commit": commit, "dirty": dirty}


def cli(plugin: Path, *args: str, cwd: Path, env: dict) -> subprocess.CompletedProcess:
    """Run the snapshot's own `bountyproof` CLI (scripts/bountyproof.py needs no install)."""
    return subprocess.run(
        [sys.executable, str(plugin / "scripts" / "bountyproof.py"), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def create(plugin: Path, parent: Path, name: str, env: dict) -> Path:
    """A black-box workspace, exactly as `bountyproof new` makes it (no git, no hunter profile)."""
    parent.mkdir(parents=True, exist_ok=True)
    proc = cli(
        plugin,
        "new",
        name,
        "--platform",
        "hackerone",
        "--mode",
        "blackbox",
        "--dir",
        str(parent),
        "--no-git",
        cwd=parent,
        env=env,
    )
    if proc.returncode:
        raise RuntimeError(f"bountyproof new failed: {proc.stderr or proc.stdout}")
    found = [p for p in parent.iterdir() if p.is_dir() and (p / "notes" / "scope.json").is_file()]
    if len(found) != 1:
        raise RuntimeError(f"expected one workspace in {parent}, found {len(found)}")
    return found[0]


def write(workspace: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = workspace / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def set_scope(workspace: Path, **fields) -> None:
    path = workspace / "notes" / "scope.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(fields)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def confirm_scope(plugin: Path, workspace: Path, env: dict) -> None:
    """The human's step at gate 1. In an eval the harness is the human: it confirms the scope it wrote."""
    proc = cli(plugin, "scope", "confirm", "--yes", cwd=workspace, env=env)
    if proc.returncode:
        raise RuntimeError(f"scope confirm failed: {proc.stderr or proc.stdout}")


def check_scope(plugin: Path, workspace: Path, target: str, env: dict) -> str:
    """allow / deny / ask / inactive, as the hook would decide (nothing is sent)."""
    proc = cli(plugin, "scope", "check", target, cwd=workspace, env=env)
    first = (proc.stdout.strip().splitlines() or [""])[0]
    return first.split()[0].lower() if first else ""


def fill_claude_md(workspace: Path, in_scope_lines: list[str]) -> None:
    """Phase 0 writes the in-scope list into CLAUDE.md; the eval does the same."""
    path = workspace / "CLAUDE.md"
    text = path.read_text(encoding="utf-8")
    text = text.replace("- TO FILL: exact hosts / apps / assets from the program page.", "\n".join(in_scope_lines))
    path.write_text(text, encoding="utf-8", newline="\n")


ARTIFACTS = ("notes", "reports", "poc", "STRATEGY.md")
SKIP = {"accounts.md"}
MAX_FILE = 2 << 20


def collect(workspace: Path, dest: Path) -> None:
    """Keep what the chain wrote (case file, reports, PoCs, egress log); skip credentials and big blobs."""
    for name in ARTIFACTS:
        src = workspace / name
        if src.is_file():
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / name)
            continue
        if not src.is_dir():
            continue
        for path in src.rglob("*"):
            if path.is_file() and path.name not in SKIP and path.stat().st_size <= MAX_FILE:
                target = dest / path.relative_to(workspace)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
