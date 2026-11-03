"""The hunter profile: your platform accounts, what you can test with, and your limits.

`bountyproof onboard` writes it once. Every new workspace gets a copy as `notes/hunter-profile.md`
so the agents plan with what you actually have, and Radar's fit score gets it as its
"Your hunter profile" section.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from bountyproof.machine import Machine
from bountyproof.workspace import PLATFORMS

DEVICES = {"android": "Android phone", "iphone": "iPhone", "mac": "Mac"}
FOCUS = {
    "web": "web apps with user accounts and user-owned data",
    "api": "REST and GraphQL APIs",
    "mobile": "mobile apps that talk to a backend API",
    "source": "source-available products I can run in a local lab",
}
LIMITS = {
    "corporate-email": "can't obtain corporate or government email accounts",
    "kyc": "can't pass KYC that needs identity documents",
    "purchases": "won't make real purchases",
}
ALWAYS_AVOID = ["network ranges and bare infrastructure", "hardware and IoT", "smart contracts"]


class ProfileError(RuntimeError):
    pass


def home() -> Path:
    return Path(os.environ.get("BOUNTYPROOF_HOME") or Path.home() / ".bountyproof")


def path() -> Path:
    return home() / "profile.json"


def default_workspaces() -> Path:
    return Path.home() / "bounties"


@dataclass
class Profile:
    platforms: dict[str, str] = field(default_factory=dict)  # platform -> username ("" if not given)
    devices: list[str] = field(default_factory=list)
    focus: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)
    hours_per_week: int = 10
    min_bounty: int = 500
    chrome_fill: bool = True  # fill the platform's report form in the hunter's Chrome (Claude in Chrome)
    workspaces_dir: str = ""
    timezone: str = ""
    machine: dict = field(default_factory=dict)
    radar: dict = field(default_factory=dict)
    created: str = ""
    version: int = 1

    @property
    def box(self) -> Machine:
        known = Machine.__dataclass_fields__
        return Machine(**{k: v for k, v in self.machine.items() if k in known})

    @property
    def phones(self) -> list[str]:
        return [d for d in self.devices if d in ("android", "iphone")]


def load() -> Profile | None:
    file = path()
    if not file.is_file():
        return None
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
        return Profile(**{k: v for k, v in data.items() if k in Profile.__dataclass_fields__})
    except (OSError, ValueError, TypeError) as exc:
        raise ProfileError(f"Can't read {file} ({exc}). Run `bountyproof onboard` again.") from exc


def save(prof: Profile) -> Path:
    file = path()
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(asdict(prof), indent=2) + "\n", encoding="utf-8")
    return file


def utc_offset() -> str:
    offset = dt.datetime.now().astimezone().utcoffset() or dt.timedelta()
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    return f"UTC{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


@dataclass(frozen=True)
class Capability:
    key: str
    label: str
    status: str  # ready | partial | missing
    detail: str


def capabilities(box: Machine, devices: list[str]) -> list[Capability]:
    caps = []

    missing = [t for t in ("claude", "node", "npx") if not box.has(t)]
    if missing:
        caps.append(Capability("web", "Web apps and APIs", "missing", f"install {', '.join(missing)}"))
    else:
        caps.append(Capability("web", "Web apps and APIs", "ready", "a real browser and curl, scope guard on"))

    phone = "android" in devices or box.android_connected > 0
    static = [t for t in ("jadx", "apktool") if box.has(t)]
    have = [*static, *(["adb"] if box.has("adb") else [])]
    if phone:
        have.append("phone connected" if box.android_connected else "phone")
    need = []
    if not static:
        need.append("install jadx to read app code")
    if not box.has("adb"):
        need.append("install Android platform-tools (adb)")
    if not phone:
        need.append("a phone for dynamic tests (reading app code works without one)")
    if not need:
        caps.append(Capability("android", "Android apps", "ready", ", ".join(have)))
    elif have:
        caps.append(Capability("android", "Android apps", "partial", f"{', '.join(have)}; {'; '.join(need)}"))
    else:
        caps.append(Capability("android", "Android apps", "missing", "install jadx to read app code; a phone helps"))

    if "iphone" not in devices and not box.iphone_connected:
        caps.append(Capability("ios", "iOS apps", "missing", "no iPhone"))
    elif box.has("idevice_id"):
        caps.append(Capability("ios", "iOS apps", "ready", "iPhone over USB (libimobiledevice)"))
    else:
        caps.append(Capability("ios", "iOS apps", "partial", "iPhone; install libimobiledevice to reach it over USB"))

    if not box.has("docker"):
        caps.append(Capability("source", "Source-available targets", "missing", "install Docker to run local labs"))
    elif not box.docker_running:
        caps.append(Capability("source", "Source-available targets", "partial", "Docker is installed but not running"))
    elif box.ram_gb and box.ram_gb < 8:
        caps.append(Capability("source", "Source-available targets", "partial", "labs will be slow under 8 GB RAM"))
    else:
        caps.append(Capability("source", "Source-available targets", "ready", "local Docker labs"))
    return caps


def _status(prof: Profile) -> dict[str, Capability]:
    return {c.key: c for c in capabilities(prof.box, prof.devices)}


def _hardware(prof: Profile) -> str:
    names = [f"one {DEVICES[d]}" if d != "mac" else "a Mac" for d in prof.devices]
    return ", ".join(names) or "no test phone"


def fit_profile(prof: Profile, today: str | None = None) -> str:
    """The "Your hunter profile" section of Radar's fit-score.md, in the rubric's own format."""
    caps = _status(prof)
    style = ["solo, black-box with AI agents driving a real browser and curl"]
    if caps["android"].status != "missing":
        style.append("Android apps (" + caps["android"].detail.split(";")[0] + ")")
    if caps["ios"].status != "missing":
        style.append("iOS apps on my own iPhone")
    if caps["source"].status == "ready":
        style.append("white-box review in a local Docker lab")
    liked = [FOCUS[f] for f in prof.focus if f in FOCUS] or [FOCUS["web"], FOCUS["api"]]
    avoided = [FOCUS[f] for f in FOCUS if f not in prof.focus] + ALWAYS_AVOID
    limits = [LIMITS[x] for x in prof.limits if x in LIMITS]
    limits.append("own no test phone" if not prof.phones else f"own no hardware beyond {_hardware(prof)}")
    lines = [
        f"> Written by `bountyproof onboard` on {today or dt.date.today().isoformat()}. Edit it freely: once",
        "> you have accepted findings, list them under *Demonstrated edge*.",
        "",
        f"- **Working style:** {'; '.join(style)}. No mass scanners.",
        "- **Strengths (bug classes):** not proven yet. Favour broken access control and business logic that",
        "  two test accounts can demonstrate.",
        f"- **Surfaces I like:** {', '.join(liked)}.",
        f"- **Surfaces I avoid:** {', '.join(avoided)}.",
        "- **Demonstrated edge (findings that were accepted and paid, not just interests):** none yet, so add",
        "  no edge points.",
        f"- **Constraints:** {'; '.join(limits)}.",
        f"- **Minimum worthwhile reward:** a max bounty of at least {prof.min_bounty:,} (EUR or USD). VDPs only",
        "  when the asset is exceptional.",
        f"- **Availability:** about {prof.hours_per_week} hours a week, {prof.timezone or utc_offset()}.",
        "",
    ]
    return "\n".join(lines)


def with_fit_profile(rubric: str, prof: Profile) -> str:
    """Replace the example profile in fit-score.md with this hunter's."""
    heading = "## Your hunter profile"
    try:
        start = rubric.index(heading)
        end = rubric.index("\n---\n", start)
    except ValueError as exc:
        raise ProfileError("fit-score.md has no 'Your hunter profile' section to fill.") from exc
    return f"{rubric[:start]}{heading}\n\n{fit_profile(prof)}{rubric[end:]}"


def hunter_notes(prof: Profile) -> str:
    """notes/hunter-profile.md for a new workspace."""
    lines = [
        "# Hunter profile",
        "",
        f"Written by `bountyproof onboard` on {prof.created or dt.date.today().isoformat()}. Plan with what is",
        "listed here: don't propose work that needs a device or tool marked missing. Run",
        "`bountyproof onboard` again after changing your setup.",
        "",
        "## Platform accounts",
        "",
    ]
    for key, user in prof.platforms.items():
        lines.append(
            f"- {PLATFORMS[key]}: `{user}`." if user else f"- {PLATFORMS[key]}: account, username not recorded."
        )
    if not prof.platforms:
        lines.append("- None recorded.")
    lines += ["", "## What this machine can do", "", "| Capability | Status | Detail |", "|---|---|---|"]
    lines += [f"| {c.label} | {c.status} | {c.detail} |" for c in capabilities(prof.box, prof.devices)]
    can_not = [LIMITS[x] for x in prof.limits if x in LIMITS]
    lines += [
        "",
        "## Capacity and limits",
        "",
        f"- Machine: {prof.box.describe()}.",
        f"- Devices: {_hardware(prof)}.",
        f"- Run at most {prof.box.parallel_slots()} browser sessions or lab containers at once.",
        f"- Time: about {prof.hours_per_week} hours a week ({prof.timezone or utc_offset()}).",
        f"- Can't: {'; '.join(can_not) or 'nothing recorded'}.",
        f"- Minimum worthwhile reward: {prof.min_bounty:,} (EUR or USD).",
        "",
        "## Report form",
        "",
        *report_form(prof.chrome_fill),
        "",
    ]
    return "\n".join(lines)


def report_form(on: bool) -> list[str]:
    """The workspace switch prompts/06b-fill-report-form.md reads (missing line = on)."""
    if on:
        return [
            "- Fill with Claude in Chrome: on",
            "",
            "When a report is READY, the agent opens the platform's report form in your Chrome with the",
            "Claude in Chrome extension, fills it from `reports/<ID>-v2.md` and stops. You read it and press",
            "submit. Write `off` above to copy and paste by hand in this workspace; run",
            "`bountyproof onboard --no-chrome-fill` to change it for new workspaces.",
        ]
    return [
        "- Fill with Claude in Chrome: off",
        "",
        "The agent hands over `reports/<ID>-v2.md` for you to paste into the form. `/bountyproof:fill <ID>`",
        "still fills it in your Chrome when you ask. Write `on` above to make it the default here.",
    ]
