"""Turn on Radar: new-program alerts on your phone, scored against your hunter profile.

Writes the workflows and a filled-in fit-score.md to a folder, and with the GitHub CLI also creates
the private repo, sets its secrets, picks a private ntfy topic and sends a test alert.
"""

from __future__ import annotations

import getpass
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from bountyproof import profile
from bountyproof.assets import assets_root
from bountyproof.workspace import PLATFORMS

WORKFLOWS = {"ywh": "radar-yeswehack.yml", "intigriti": "radar-intigriti.yml", "hackerone": "radar-hackerone.yml"}
# secret -> (prompt, platform that can't run without it)
SECRETS = {
    "INTIGRITI_TOKEN": ("Intigriti researcher API token (Intigriti > account settings)", "intigriti"),
    "H1_USERNAME": ("HackerOne username", "hackerone"),
    "H1_TOKEN": ("HackerOne API token (hackerone.com > Settings > API token)", "hackerone"),
    "ANTHROPIC_API_KEY": ("Anthropic API key to score each program against your profile", None),
}
NTFY = "https://ntfy.sh"


class RadarError(RuntimeError):
    pass


def default_dir() -> Path:
    return Path.home() / "bountyproof-radar"


def platforms_for(prof: profile.Profile) -> list[str]:
    """Platforms to watch: the ones you have accounts on, or YesWeHack's public listing if none."""
    return [p for p in WORKFLOWS if p in prof.platforms] or ["ywh"]


def write(dest: Path, prof: profile.Profile) -> list[str]:
    if dest.exists() and any(dest.iterdir()):
        raise RadarError(f"{dest} already exists and isn't empty.")
    src = assets_root() / "radar"
    watched = platforms_for(prof)
    workflows = dest / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for key in watched:
        shutil.copyfile(src / "workflows" / WORKFLOWS[key], workflows / WORKFLOWS[key])
    state = dest / "radar" / "state"
    state.mkdir(parents=True)
    (state / ".gitkeep").touch()
    rubric = (src / "fit-score.md").read_text(encoding="utf-8")
    (dest / "radar" / "fit-score.md").write_text(profile.with_fit_profile(rubric, prof), encoding="utf-8")
    shutil.copyfile(src / "README.md", dest / "README.md")
    return watched


def needed_secrets(watched: list[str]) -> list[str]:
    return [name for name, (_, platform) in SECRETS.items() if platform is None or platform in watched]


def _run(cmd: list[str], cwd: Path | None = None, stdin: str | None = None, check: bool = True):
    try:
        out = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RadarError(f"`{' '.join(cmd[:3])}` failed: {exc}") from exc
    if check and out.returncode != 0:
        raise RadarError(f"`{' '.join(cmd[:3])}` failed: {(out.stderr or out.stdout).strip()[:300]}")
    return out


def gh_ready() -> bool:
    return shutil.which("gh") is not None and _run(["gh", "auth", "status"], check=False).returncode == 0


def publish(dest: Path, repo_name: str) -> str:
    """Commit the folder and push it to a new private repo. Returns owner/name."""
    _run(["git", "init", "-q", "-b", "main"], dest)
    _run(["git", "add", "-A"], dest)
    try:
        _run(["git", "commit", "-q", "-m", "Add bountyproof Radar"], dest)
    except RadarError as exc:
        raise RadarError(f"{exc}\nSet your git identity (git config --global user.name / user.email).") from exc
    _run(["gh", "repo", "create", repo_name, "--private", "--source", ".", "--push"], dest)
    return _run(["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"], dest).stdout.strip()


def set_secret(repo: str, name: str, value: str) -> None:
    _run(["gh", "secret", "set", name, "--repo", repo], stdin=value)  # stdin keeps it out of the process list


def dispatch(repo: str, workflow: str, *inputs: str) -> bool:
    args = [arg for value in inputs for arg in ("-f", value)]
    for _ in range(6):  # a freshly pushed workflow takes a few seconds to register
        if _run(["gh", "workflow", "run", workflow, "--repo", repo, *args], check=False).returncode == 0:
            return True
        time.sleep(5)
    return False


def _phone_steps(topic: str) -> str:
    return (
        "Phone alerts\n"
        "  1. Install the ntfy app (Android or iOS). It's free and needs no account.\n"
        f"  2. Subscribe to this topic: {topic}\n"
        f"     (or open {NTFY}/{topic} in a browser)\n"
        "  Keep the topic name to yourself: anyone who knows it can read your alerts."
    )


def manual_steps(dest: Path, watched: list[str], topic: str) -> str:
    names = ", ".join(n for n in needed_secrets(watched) if n != "ANTHROPIC_API_KEY")
    return "\n".join(
        [
            f"To turn Radar on from {dest}:",
            "  1. Create a PRIVATE GitHub repository and push this folder to it.",
            f"  2. Add repository secrets: NTFY_TOPIC = {topic}"
            + (f", plus {names}" if names else "")
            + ". ANTHROPIC_API_KEY is optional (it scores each program).",
            "  3. Actions > Radar > Run workflow. The first run is a silent baseline; tick test_alert to try it.",
            "",
            _phone_steps(topic),
        ]
    )


def setup(
    prof: profile.Profile,
    dest: Path,
    repo_name: str = "bountyproof-radar",
    github: bool = True,
    ask: Callable[[str], str] = input,
    secret: Callable[[str], str] = getpass.getpass,
) -> profile.Profile:
    """Write Radar to `dest` and, if the user agrees, put it live on GitHub. Returns the updated profile."""
    watched = write(dest, prof)
    topic = f"bountyproof-{secrets.token_hex(10)}"
    prof.radar = {"dir": str(dest), "ntfy_topic": topic, "platforms": watched}
    print(f"\nRadar written to {dest}, watching {', '.join(PLATFORMS[p] for p in watched)}.")

    if not github or not gh_ready():
        if github:
            print("The GitHub CLI isn't installed or logged in (`gh auth login`), so finish by hand:\n")
        print(manual_steps(dest, watched, topic))
        return prof
    if ask(f"Create the private GitHub repo '{repo_name}' and push it? [Y/n] ").strip().lower() in ("n", "no"):
        print(manual_steps(dest, watched, topic))
        return prof

    repo = publish(dest, repo_name)
    prof.radar["repo"] = repo
    print(f"Pushed to https://github.com/{repo} (private).")
    set_secret(repo, "NTFY_TOPIC", topic)

    blocked = set()
    for name in needed_secrets(watched):
        label, platform = SECRETS[name]
        value = prof.platforms.get("hackerone", "") if name == "H1_USERNAME" else ""
        if not value:
            hint = "alerts arrive unscored" if platform is None else f"{PLATFORMS[platform]} stays off"
            value = secret(f"  {label} (Enter to skip, {hint}): ").strip()
        if value:
            set_secret(repo, name, value)
        elif platform:
            blocked.add(platform)

    print("\n" + _phone_steps(topic))
    ask("\nPress Enter once you're subscribed. ")
    live = [p for p in watched if p not in blocked]
    for key in live:
        dispatch(repo, WORKFLOWS[key])  # silent baseline: records today's programs, alerts start after it
    if live and dispatch(repo, WORKFLOWS[live[0]], "test_alert=true"):
        print("A test alert is on its way to your phone (a minute or two).")
    for key in sorted(blocked):
        _run(["gh", "workflow", "disable", WORKFLOWS[key], "--repo", repo], check=False)  # no hourly failures
        print(
            f"{PLATFORMS[key]} is off until you add its token: gh secret set <NAME> --repo {repo}, "
            f"then gh workflow enable {WORKFLOWS[key]} --repo {repo}"
        )
    return prof
