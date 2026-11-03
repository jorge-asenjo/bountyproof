"""`bountyproof onboard`: detect the machine, ask what detection can't tell, save the hunter profile."""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from dataclasses import asdict
from pathlib import Path

from bountyproof import machine, profile, radar
from bountyproof.profile import DEVICES, FOCUS, LIMITS, Profile, ProfileError
from bountyproof.workspace import PLATFORMS

SIGNUP = {
    "hackerone": "https://hackerone.com",
    "ywh": "https://yeswehack.com",
    "intigriti": "https://www.intigriti.com",
}
STATUS_ORDER = {"ready": 0, "partial": 1, "missing": 2}


def _pick(question: str, options: dict[str, str], marked: list[str]) -> list[str]:
    keys = list(options)
    print(f"\n{question}")
    for i, key in enumerate(keys, 1):
        print(f"  [{'x' if key in marked else ' '}] {i}. {options[key]}")
    while True:
        raw = input("  Numbers separated by commas, Enter keeps the marked ones, 0 for none: ").strip()
        if not raw:
            return marked
        if raw == "0":
            return []
        try:
            numbers = [int(x) for x in raw.replace(" ", ",").split(",") if x]
        except ValueError:
            numbers = [0]
        if numbers and all(1 <= n <= len(keys) for n in numbers):
            return list(dict.fromkeys(keys[n - 1] for n in numbers))
        print("  Use the numbers from the list.")


def _number(question: str, default: int) -> int:
    while True:
        raw = input(f"\n{question} [{default}]: ").strip()
        if not raw:
            return default
        if raw.isdigit():
            return int(raw)
        print("  A whole number, please.")


def _yes(question: str) -> bool:
    return input(f"\n{question} [Y/n] ").strip().lower() not in ("n", "no")


def _parse_platforms(values: list[str] | None) -> dict[str, str] | None:
    if values is None:
        return None
    out = {}
    for value in values:
        key, _, user = value.partition(":")
        if key == "none":
            continue
        if key not in PLATFORMS:
            raise ProfileError(f"Unknown platform {key!r}. Use one of: {', '.join(PLATFORMS)}, none.")
        out[key] = user.strip()
    return out


def _listed(values: list[str] | None) -> list[str] | None:
    return None if values is None else [v for v in values if v != "none"]


def _ask_platforms() -> dict[str, str]:
    picked = _pick("Where do you have a researcher account? (all three are free to join)", PLATFORMS, [])
    accounts = {key: input(f"  Your {PLATFORMS[key]} username (Enter to skip): ").strip() for key in picked}
    if not accounts:
        print("  No account yet: sign up on one before your first program.")
        print("  " + "  ".join(SIGNUP.values()))
        print("  Radar can already watch YesWeHack's public listing for you.")
    return accounts


def default_devices(box: machine.Machine) -> list[str]:
    found = []
    if box.android_connected:
        found.append("android")
    if box.iphone_connected:
        found.append("iphone")
    if box.is_mac:
        found.append("mac")
    return found


def default_focus(box: machine.Machine, devices: list[str]) -> list[str]:
    focus = ["web", "api"]
    if any(d in devices for d in ("android", "iphone")) or box.has("jadx"):
        focus.append("mobile")
    if box.docker_running:
        focus.append("source")
    return focus


def collect(args: argparse.Namespace, box: machine.Machine, interactive: bool) -> Profile:
    platforms = _parse_platforms(args.platform)
    devices = _listed(args.device)
    focus = _listed(args.focus)
    limits = _listed(args.cant)

    if platforms is None:
        platforms = _ask_platforms() if interactive else {}
    if devices is None:
        detected = default_devices(box)
        question = "Which devices can you test with? (phones plugged in over USB are already marked)"
        devices = _pick(question, DEVICES, detected) if interactive else detected
    if focus is None:
        suggested = default_focus(box, devices)
        focus = _pick("What do you want to hunt?", FOCUS, suggested) if interactive else suggested
    if limits is None:
        limits = (
            _pick("Anything you can't do? Radar will skip programs that need it.", LIMITS, []) if interactive else []
        )
    hours = (
        args.hours if args.hours is not None else (_number("Hours a week for bug bounty?", 10) if interactive else 10)
    )
    min_bounty = args.min_bounty
    if min_bounty is None:
        min_bounty = _number("Smallest top bounty worth your time (EUR or USD)?", 500) if interactive else 500
    chrome_fill = args.chrome_fill
    if chrome_fill is None:
        question = "Fill the report form for you in Chrome (Claude in Chrome extension)? You still press submit."
        chrome_fill = _yes(question) if interactive else True
    workspaces = args.workspaces or str(profile.default_workspaces())

    return Profile(
        platforms=platforms,
        devices=devices,
        focus=focus,
        limits=limits,
        hours_per_week=hours,
        min_bounty=min_bounty,
        chrome_fill=chrome_fill,
        workspaces_dir=str(Path(workspaces).expanduser().resolve()),
        timezone=profile.utc_offset(),
        machine=asdict(box),
        created=dt.date.today().isoformat(),
    )


def render_machine(box: machine.Machine) -> str:
    phones = []
    if box.android_connected:
        phones.append(f"Android x{box.android_connected}")
    if box.iphone_connected:
        phones.append(f"iPhone x{box.iphone_connected}")
    docker = " (running)" if box.docker_running else (" (not running)" if box.has("docker") else "")
    tools = ", ".join(t + (docker if t == "docker" else "") for t in box.tools) or "none"
    return "\n".join(
        [
            "Your machine",
            f"  {box.describe()}",
            f"  Phones over USB: {', '.join(phones) or 'none'}",
            f"  Tools found: {tools}",
        ]
    )


def render_capabilities(prof: Profile) -> str:
    box = prof.box
    caps = sorted(profile.capabilities(box, prof.devices), key=lambda c: STATUS_ORDER[c.status])
    lines = ["What you can hunt"]
    lines += [f"  {c.status:<9} {c.label:<26} {c.detail}" for c in caps]
    lines.append(f"  Room for {box.parallel_slots()} browser sessions or labs at once.")
    return "\n".join(lines)


def next_steps(prof: Profile) -> str:
    platform = next(iter(prof.platforms), "hackerone")
    lines = ["", "Next"]
    if not prof.radar.get("repo"):
        lines.append("  Turn on phone alerts for new programs:  bountyproof radar init")
    lines += [
        "  When an alert arrives, paste its command. It creates the workspace and starts the agents:",
        f'    bountyproof start "Program name" --platform {platform} --url <program URL>',
    ]
    if prof.chrome_fill:
        lines += [
            "  You approve the scope. The agents hunt, prove, draft the report and fill the platform's form",
            "  in your Chrome. You press submit. That last step needs the Claude in Chrome extension: install",
            "  it from the Chrome Web Store, sign in to your platforms in Chrome, and run /chrome in Claude Code.",
        ]
    else:
        lines.append("  You approve the scope. The agents hunt, prove and draft the report. You press submit.")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    print("Checking this machine...\n")
    box = machine.detect()
    print(render_machine(box))
    if args.detect:
        prof = Profile(devices=default_devices(box), machine=asdict(box))
        print("\n" + render_capabilities(prof))
        return 0

    interactive = not args.yes and sys.stdin.isatty()
    if interactive:
        print("\nA few questions. Enter accepts what's marked or in brackets.")
    prof = collect(args, box, interactive)
    previous = profile.load()
    if previous and previous.radar:
        prof.radar = previous.radar  # re-onboarding keeps an existing Radar setup

    print("\n" + render_capabilities(prof))
    saved = profile.save(prof)
    print(f"\nSaved {saved}")
    print(f"New workspaces go to {prof.workspaces_dir}")

    if interactive and not args.no_radar and not prof.radar.get("dir"):
        print("\nRadar watches the platforms and pings your phone when a program that fits you launches.")
        if input("Set it up now? [Y/n] ").strip().lower() not in ("n", "no"):
            try:
                prof = radar.setup(prof, radar.default_dir())
            except radar.RadarError as exc:
                print(f"Radar setup stopped: {exc}\nRun `bountyproof radar init` to try again.")
            profile.save(prof)
    print(next_steps(prof))
    return 0
