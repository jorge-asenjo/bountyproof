"""bountyproof command line."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from bountyproof import __version__, doctor, funnel, onboard, profile, radar, scope, scope_import, workspace
from bountyproof.assets import AssetsNotFound

EXIT_DENY = 2
EXIT_ASK = 3


def _find_workspace(start: Path) -> Path:
    for path in (start, *start.parents):
        if (path / "notes" / "scope.json").is_file():
            return path
    raise scope.ScopeError("Not inside an engagement workspace (no notes/scope.json found).")


def _create(args: argparse.Namespace) -> tuple[workspace.Engagement, Path]:
    """Create the workspace, taking the folder, platform and hunter notes from the profile if there is one."""
    prof = profile.load()
    platform = args.platform
    if platform is None:
        platform = next(iter(prof.platforms)) if prof and len(prof.platforms) == 1 else "hackerone"
    parent = Path(args.dir or (prof.workspaces_dir if prof and prof.workspaces_dir else "."))
    parent.mkdir(parents=True, exist_ok=True)
    eng = workspace.Engagement(args.name, platform, args.mode, args.stack)
    notes = profile.hunter_notes(prof) if prof else None
    return eng, workspace.create(eng, parent, init_git=not args.no_git, hunter_profile=notes)


def cmd_new(args: argparse.Namespace) -> int:
    eng, dest = _create(args)
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
    eng, dest = _create(args)
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
    review = data.get("needsReview") if isinstance(data.get("needsReview"), list) else []
    if review:
        print(f"  NEEDS REVIEW   {len(review)} listed by the program but NOT rules (needsReview):")
        for item in review[:15]:
            print(f"    - {_review_line(item)}")
    errors = scope.compile_scope(data).errors
    if errors:
        print("The guard can't enforce this file as written, so confirming it won't unblock anything:")
        for err in errors[:10]:
            print(f"  - {err}")
        return 1
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


def _review_line(item: object) -> str:
    if not isinstance(item, dict):
        return str(item)
    side = "in" if item.get("side") == "in" else "out"
    line = f"[{side}] {item.get('asset', '')}: {item.get('why', '')}"
    return line + (f" (suggested rule: {item['suggest']})" if item.get("suggest") else "")


def _rules(items: list[str]) -> str:
    return f"{len(items)} rule{'' if len(items) == 1 else 's'}"


def _sample(items: list[str], n: int = 6) -> str:
    return ", ".join(items[:n]) + (f", ... (+{len(items) - n})" if len(items) > n else "")


def cmd_scope_import(args: argparse.Namespace) -> int:
    if bool(args.ref) == bool(args.text):
        print(
            "error: give one source: a program (h1:<handle>, bugcrowd:<handle>, intigriti:<company>/<handle>, "
            "yeswehack:<id> or its URL), or --text FILE with the scope pasted from the program page",
            file=sys.stderr,
        )
        return 2
    ws = _find_workspace(Path.cwd())
    scope_file = ws / "notes" / "scope.json"
    current = scope.load(scope_file)
    if not isinstance(current, dict):
        raise scope.ScopeError(f"{scope_file} must be a JSON object: fix it before importing.")
    try:
        text = None
        if args.text:
            text = sys.stdin.read() if args.text == "-" else Path(args.text).read_text(encoding="utf-8")
        program = scope_import.load_program(
            args.ref,
            text=text,
            name=args.name,
            data=args.data,
            refresh=args.refresh,
            log=lambda msg: print(msg, file=sys.stderr),
        )
    except (ValueError, LookupError, OSError, scope_import.ScopeImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    res = scope_import.apply(current, program, whitebox=scope_import.is_whitebox(ws))

    title = f"{scope_import.PLATFORM_NAMES.get(program.platform, 'pasted text')} {program.handle}".strip()
    print(
        f"Scope of {title}{f' ({program.name})' if program.name and program.name != program.handle else ''}, "
        f"from {program.source}:"
    )
    if res.whitebox:
        print(f"  out of scope   {_rules(res.imported_out)} (white-box: every program asset; the lab is the target)")
    else:
        print(f"  in scope       {_rules(res.imported_in)}  {_sample(res.imported_in)}".rstrip())
        print(f"  out of scope   {_rules(res.imported_out)}  {_sample(res.imported_out)}".rstrip())
        if res.imported_unlisted:
            print(f"  unlisted = out {_rules(res.imported_unlisted)}  {_sample(res.imported_unlisted)}")
            print(
                "                 (excluded wildcards over hosts the program lists in scope: everything else "
                "under them is out, the listed hosts stay in)"
            )
    if res.kept_in or res.kept_out:
        print(f"  kept by hand   {len(res.kept_in)} in scope, {len(res.kept_out)} out of scope")
    if res.review:
        print(f"  needs review   {len(res.review)}, NOT rules until you write them yourself:")
        for item in res.review[:12]:
            print(f"    - {_review_line(item)}")
        if len(res.review) > 12:
            print(f"    ... and {len(res.review) - 12} more in notes/scope.json (needsReview)")
    if res.other:
        print(f"  other assets   {len(res.other)} (apps, source code, hardware: not hosts, listed in otherAssets)")
    for name in res.conflicts:
        print(f"warning: {name} is in inScope by hand, but the program lists it out of scope. Out of scope wins.")
    if program.conduct or program.exclusions:
        print("Found in the program text (copy what applies into notes/program-rules.md):")
        for line in (program.conduct + [f"not eligible: {x}" for x in program.exclusions])[:15]:
            print(f"  - {line}")
    if not res.whitebox and not res.scope["inScope"]:
        print(
            "warning: no in-scope rule came out of this: the guard denies every target until hosts are added by hand."
        )
    errors = scope.compile_scope(res.scope).errors
    for err in errors[:10]:
        print(f"warning: notes/scope.json still has an entry the guard can't enforce: {err}")
    if args.dry_run:
        print("Dry run: nothing written.")
        return 0
    scope.save(scope_file, res.scope)
    print(f"Wrote {scope_file}.")
    if res.changed and current.get("requireConfirm") is True:
        print(
            "The scope changed, so live testing stays blocked until you check notes/scope.json against the "
            "program page and run `bountyproof scope confirm` in your own terminal."
        )
    elif res.changed:
        print("The scope changed. requireConfirm is off in this workspace, so the new rules apply now.")
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


def cmd_onboard(args: argparse.Namespace) -> int:
    return onboard.run(args)


def cmd_radar_init(args: argparse.Namespace) -> int:
    prof = profile.load()
    if prof is None:
        raise profile.ProfileError("No hunter profile yet. Run `bountyproof onboard` first.")
    dest = Path(args.dir).expanduser().resolve() if args.dir else radar.default_dir()
    prof = radar.setup(prof, dest, repo_name=args.repo, github=not args.no_github)
    profile.save(prof)
    return 0


def _shell_path(path: Path) -> str:
    text = str(path)
    return f'"{text}"' if " " in text else text


def _add_engagement_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="program name, e.g. 'Acme Corp'")
    p.add_argument(
        "--platform",
        choices=sorted(workspace.PLATFORMS),
        help="default: your only platform in the hunter profile, else hackerone",
    )
    p.add_argument(
        "--mode",
        choices=workspace.MODES,
        default="blackbox",
        help="blackbox = live target via browser + curl; whitebox = source + local Docker lab",
    )
    p.add_argument("--stack", choices=workspace.STACKS, default="custom", help="Docker template (whitebox)")
    p.add_argument("--dir", help="parent folder for the workspace (default: the profile's, else the current folder)")
    p.add_argument("--no-git", action="store_true", help="don't initialise a local git repo")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bountyproof",
        description="A team of AI agents for bug bounties. They hunt, prove it and draft the report; you submit.",
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
    s = scope_sub.add_parser("import", help="fill notes/scope.json from the program's published scope")
    s.add_argument(
        "ref",
        nargs="?",
        help="h1:<handle>, bugcrowd:<handle>, intigriti:<company>/<handle>, yeswehack:<id>, or the program URL",
    )
    s.add_argument("--text", metavar="FILE", help="the scope pasted from the program page into a file ('-' = stdin)")
    s.add_argument("--name", help="the program's name, with --text")
    s.add_argument("--data", metavar="FILE", help="a bounty-targets-data dump on disk instead of downloading it")
    s.add_argument("--refresh", action="store_true", help="download the dump again even if the cached copy is fresh")
    s.add_argument("--dry-run", action="store_true", help="show the result without writing it")
    s.set_defaults(func=cmd_scope_import)

    p = sub.add_parser("funnel", help="show how many hypotheses survived each gate")
    p.add_argument("workspace", nargs="?", default=".")
    p.set_defaults(func=cmd_funnel)

    p = sub.add_parser("doctor", help="check the local toolchain")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("onboard", help="set up your hunter profile: accounts, devices, tools and limits")
    p.add_argument("--detect", action="store_true", help="only show what this machine has; save nothing")
    p.add_argument("--yes", action="store_true", help="don't ask: use the flags given and defaults for the rest")
    p.add_argument("--platform", action="append", metavar="NAME[:USER]", help="ywh, intigriti, hackerone or none")
    p.add_argument("--device", action="append", choices=[*profile.DEVICES, "none"])
    p.add_argument("--focus", action="append", choices=[*profile.FOCUS, "none"])
    p.add_argument("--cant", action="append", choices=[*profile.LIMITS, "none"], help="things you can't do")
    p.add_argument("--hours", type=int, help="hours a week")
    p.add_argument("--min-bounty", type=int, help="smallest top bounty worth your time")
    p.add_argument("--workspaces", help="folder for new workspaces (default: ~/bounties)")
    p.add_argument(
        "--chrome-fill",
        action=argparse.BooleanOptionalAction,
        help="fill the platform's report form in your Chrome with Claude in Chrome (default: on)",
    )
    p.add_argument("--no-radar", action="store_true", help="don't offer to set up Radar")
    p.set_defaults(func=cmd_onboard)

    p = sub.add_parser("radar", help="phone alerts for new programs that fit your profile")
    radar_sub = p.add_subparsers(dest="radar_command", required=True)
    r = radar_sub.add_parser("init", help="write Radar for your profile and put it live in a private GitHub repo")
    r.add_argument("dir", nargs="?", help="folder to create (default: ~/bountyproof-radar)")
    r.add_argument("--repo", default="bountyproof-radar", help="name of the private repo to create")
    r.add_argument("--no-github", action="store_true", help="only write the files")
    r.set_defaults(func=cmd_radar_init)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (workspace.WorkspaceError, scope.ScopeError, profile.ProfileError, radar.RadarError, AssetsNotFound) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
