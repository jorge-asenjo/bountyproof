"""Scaffold an engagement workspace from the template."""

from __future__ import annotations

import datetime as dt
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from bountyproof.assets import assets_root

PLATFORMS = {"ywh": "YesWeHack", "intigriti": "Intigriti", "hackerone": "HackerOne"}
MODES = ("blackbox", "whitebox")
STACKS = ("java", "custom")
PLACEHOLDER_FILES = ("CLAUDE.md", "PLAN.md", "STRATEGY.md")


class WorkspaceError(RuntimeError):
    pass


@dataclass(frozen=True)
class Engagement:
    name: str
    platform: str = "hackerone"
    mode: str = "blackbox"
    stack: str = "custom"

    @property
    def platform_name(self) -> str:
        return PLATFORMS[self.platform]

    @property
    def folder(self) -> str:
        return f"{slugify(self.name)}-{self.platform}"


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not slug:
        raise WorkspaceError(f"Program name {text!r} has no usable characters.")
    return slug


def create(eng: Engagement, parent: Path, init_git: bool = True, hunter_profile: str | None = None) -> Path:
    if eng.platform not in PLATFORMS:
        raise WorkspaceError(f"Unknown platform {eng.platform!r}. Use one of: {', '.join(PLATFORMS)}.")
    if eng.mode not in MODES:
        raise WorkspaceError(f"Unknown mode {eng.mode!r}. Use one of: {', '.join(MODES)}.")
    if eng.stack not in STACKS:
        raise WorkspaceError(f"Unknown stack {eng.stack!r}. Use one of: {', '.join(STACKS)}.")

    src = assets_root()
    dest = parent.expanduser().resolve() / eng.folder
    if dest.exists():
        raise WorkspaceError(f"{dest} already exists.")

    shutil.copytree(src / "template", dest)

    # The mode decides which rules file becomes the workspace's CLAUDE.md.
    shutil.copyfile(dest / f"CLAUDE.{eng.mode}.md", dest / "CLAUDE.md")
    for mode in MODES:
        (dest / f"CLAUDE.{mode}.md").unlink()

    values = {
        "{{PROGRAM_NAME}}": eng.name,
        "{{DATE}}": dt.date.today().isoformat(),
        "{{PLATFORM}}": eng.platform,
        "{{PLATFORM_NAME}}": eng.platform_name,
    }
    for name in PLACEHOLDER_FILES:
        path = dest / name
        text = path.read_text(encoding="utf-8")
        for key, value in values.items():
            text = text.replace(key, value)
        path.write_text(text, encoding="utf-8")

    if eng.mode == "whitebox":
        shutil.copyfile(dest / "docker" / f"docker-compose.{eng.stack}.yml", dest / "docker" / "docker-compose.yml")
        (dest / "source").mkdir()
    else:
        shutil.rmtree(dest / "docker")
        # Live targets: no testing until a human has checked the scope against the program page.
        scope_file = dest / "notes" / "scope.json"
        text = scope_file.read_text(encoding="utf-8")
        scope_file.write_text(text.replace('"requireConfirm": false', '"requireConfirm": true', 1), encoding="utf-8")

    shutil.copytree(src / "prompts", dest / "prompts")
    shutil.copytree(src / "reference", dest / "reference")
    forms = dest / "reference"
    shutil.copyfile(forms / f"{eng.platform}-form-reference.md", forms / "form-reference.md")
    for platform in PLATFORMS:
        (forms / f"{platform}-form-reference.md").unlink()

    hooks = dest / ".claude" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src / "hooks" / "scope-guard.mjs", hooks / "scope-guard.mjs")
    (dest / "reports").mkdir(exist_ok=True)
    if hunter_profile:
        (dest / "notes" / "hunter-profile.md").write_text(hunter_profile, encoding="utf-8")

    if init_git:
        _git_init(dest, eng)
    return dest


def _git(dest: Path, *args: str) -> int:
    return subprocess.run(
        ["git", *args], cwd=dest, capture_output=True, text=True, encoding="utf-8", errors="replace"
    ).returncode


def _git_init(dest: Path, eng: Engagement) -> None:
    # Local-only history. A private-program workspace must never get a public remote.
    if shutil.which("git") is None or _git(dest, "init", "-q") != 0:
        return
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m", f"Initial setup: {eng.name} ({eng.mode})")
