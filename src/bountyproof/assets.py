"""Locate the files a workspace is built from (template, prompts, reference, hook).

Installed wheels carry them under ``bountyproof/_assets``. A git checkout (or the Claude Code plugin
cache, which is a checkout) has them at the repository root.
"""

from __future__ import annotations

from pathlib import Path

_MARKER = Path("template") / "CLAUDE.blackbox.md"


class AssetsNotFound(RuntimeError):
    pass


def assets_root() -> Path:
    here = Path(__file__).resolve().parent
    bundled = here / "_assets"
    if (bundled / _MARKER).is_file():
        return bundled
    for parent in here.parents:
        if (parent / _MARKER).is_file() and (parent / "prompts").is_dir():
            return parent
    raise AssetsNotFound("Can't find the bountyproof template. Reinstall the package or run from a git checkout.")


def hook_path() -> Path:
    return assets_root() / "hooks" / "scope-guard.mjs"
