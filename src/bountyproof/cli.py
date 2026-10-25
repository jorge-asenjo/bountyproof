"""bountyproof command line."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from bountyproof import __version__, doctor, funnel, scope, workspace
from bountyproof.assets import AssetsNotFound

EXIT_DENY = 2
EXIT_ASK = 3


def _find_workspace(start: Path) -> Path:
    for path in (start, *start.parents):
        if (path / "notes" / "scope.json").is_file():
            return path
    raise scope.ScopeError("Not inside an engagement workspace (no notes/scope.json found).")


def cmd_new(args: argparse.Namespace) -> int:
    eng = workspace.Engagement(args.name, args.platform, args.mode, args.stack)
    dest = workspace.create(eng, Path(args.dir), init_git=not args.no_git)
    print(f"Created {dest}  (mode={eng.mode}, platform={eng.platform_name})")
    print("Keep this workspace's git history local: never push a private-program workspace.")
    print("\nNext:")
    print(f"  cd {_shell_path(dest)}")
    if eng.mode == "blackbox":
        print("  edit .mcp.json if the program requires a UA tag, then start `claude` here")
    else:
        print("  start `claude` here")
    print("  /bountyproof:setup <program URL>   (or: 'Run Phase 0 for <program URL>')")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    eng = workspace.Engagement(args.name, args.platform, args.mode, args.stack)
    dest = workspace.create(eng, Path(args.dir), init_git=not args.no_git)
    prompt = "Run Phase 0 (prompts/00-setup-program.md) for this program."
    if args.url:
        prompt += f" {eng.platform_name} program URL: {args.url}"
    print(f"Created {dest}")
    if args.no_launch or shutil.which("claude") is None:
        print(f'\nStart it with:\n  cd {_shell_path(dest)}\n  claude "{prompt}"')
        return 0
    return subprocess.call(["claude", prompt], cwd=dest)


def cmd_scope_check(args: argparse.Namespace) -> int:
    ws = _find_workspace(Path.cwd())
    verdict = scope.check(ws, args.target, ua=args.ua)
    print(f"{verdict.decision.upper()}  {args.target}")
    if verdict.reason:
        print(f"  {verdict.reason}")
    return {"deny": EXIT_DENY, "ask": EXIT_ASK}.get(verdict.decision, 0)


def cmd_scope_confirm(args: argparse.Namespace) -> int:
    ws = _find_workspace(Path.cwd())
    scope_file = ws / "notes" / "scope.json"
    data = scope.load(scope_file)
    print("Scope to confirm:")
    for key, label in (("inScope", "IN SCOPE"), ("outOfScope", "OUT OF SCOPE"), ("denyUnlisted", "DENY UNLISTED")):
        print(f"  {label:<14} {', '.join(map(str, data.get(key) or [])) or '-'}")
    if data.get("confirmedScope") == scope.scope_hash(data):
        print("Already confirmed: the scope hasn't changed since the last confirmation.")
        return 0
    if not args.yes:
        answer = input("Is this exactly the scope you are authorized to test? (yes/no) ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Not confirmed. Nothing written.")
            return 1
    digest = scope.confirm(scope_file, data)
    print(f"Confirmed. confirmedScope = {digest}")
    return 0


def cmd_scope_hash(args: argparse.Namespace) -> int:
    ws = _find_workspace(Path.cwd())
    print(scope.scope_hash(scope.load(ws / "notes" / "scope.json")))
    return 0


def cmd_funnel(args: argparse.Namespace) -> int:
    ws = _find_workspace(Path(args.workspace).resolve())
    print(funnel.render(funnel.parse(ws / "notes" / "case-file.md"), ws.name))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    return doctor.run()


def _shell_path(path: Path) -> str:
    text = str(path)
    return f'"{text}"' if " " in text else text


def _add_engagement_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="program name, e.g. 'Acme Corp'")
    p.add_argument("--platform", choices=sorted(workspace.PLATFORMS), default="hackerone")
    p.add_argument(
        "--mode",
        choices=workspace.MODES,
        default="blackbox",
        help="blackbox = live target via browser + curl; whitebox = source + local Docker lab",
    )
    p.add_argument("--stack", choices=workspace.STACKS, default="custom", help="Docker template (whitebox)")
    p.add_argument("--dir", default=".", help="parent folder for the workspace (default: current folder)")
    p.add_argument("--no-git", action="store_true", help="don't initialise a local git repo")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bountyproof",
        description="Evidence-gated, scope-enforced agent harness for bug bounty work.",
    )
    parser.add_argument("--version", action="version", version=f"bountyproof {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("new", help="create an engagement workspace")
    _add_engagement_args(p)
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("start", help="create a workspace and launch Claude Code on Phase 0")
    _add_engagement_args(p)
    p.add_argument("--url", help="program page URL")
    p.add_argument("--no-launch", action="store_true", help="print the launch command instead of running it")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("scope", help="check or confirm the workspace scope")
    scope_sub = p.add_subparsers(dest="scope_command", required=True)
    s = scope_sub.add_parser("check", help="ask the scope guard what it would do (nothing is sent)")
    s.add_argument("target", help="a URL, or a full command in quotes")
    s.add_argument("--ua", help="user agent to test with (default: the scope's uaTag)")
    s.set_defaults(func=cmd_scope_check)
    s = scope_sub.add_parser("confirm", help="record a human confirmation of the current scope")
    s.add_argument("--yes", action="store_true", help="skip the interactive question")
    s.set_defaults(func=cmd_scope_confirm)
    s = scope_sub.add_parser("hash", help="print the hash of the current scope")
    s.set_defaults(func=cmd_scope_hash)

    p = sub.add_parser("funnel", help="show how many hypotheses survived each gate")
    p.add_argument("workspace", nargs="?", default=".")
    p.set_defaults(func=cmd_funnel)

    p = sub.add_parser("doctor", help="check the local toolchain")
    p.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (workspace.WorkspaceError, scope.ScopeError, AssetsNotFound) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
