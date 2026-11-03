import json

import pytest

from bountyproof import cli, machine, onboard, profile, radar

LAPTOP = machine.Machine(
    os="Windows 11",
    cpus=16,
    ram_gb=32.0,
    disk_free_gb=400.0,
    tools=["claude", "node", "git", "npx", "docker", "adb", "jadx", "gh"],
    docker_running=True,
    android_connected=1,
)


@pytest.fixture
def laptop(monkeypatch):
    monkeypatch.setattr(machine, "detect", lambda: LAPTOP)
    return LAPTOP


def test_onboard_from_flags_saves_the_profile(laptop, tmp_path):
    code = cli.main(
        ["onboard", "--yes", "--platform", "hackerone:jdoe", "--platform", "ywh", "--cant", "kyc", "--hours", "6"]
        + ["--workspaces", str(tmp_path / "ws")]
    )
    assert code == 0
    prof = profile.load()
    assert prof.platforms == {"hackerone": "jdoe", "ywh": ""}
    assert prof.devices == ["android"]  # the phone plugged in over USB
    assert prof.focus == ["web", "api", "mobile", "source"]
    assert prof.limits == ["kyc"] and prof.hours_per_week == 6 and prof.min_bounty == 500
    assert prof.box.android_connected == 1


def test_detect_saves_nothing(laptop, capsys):
    assert cli.main(["onboard", "--detect"]) == 0
    out = capsys.readouterr().out
    assert "16 cores, 32 GB RAM" in out and "Android apps" in out
    assert profile.load() is None


def test_interactive_answers(laptop, monkeypatch, tmp_path):
    answers = iter(["3", "jdoe", "", "1,2", "0", "", "1000", "n", "n"])  # no Chrome form fill, no radar
    monkeypatch.setattr("builtins.input", lambda _="": next(answers))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert cli.main(["onboard", "--workspaces", str(tmp_path)]) == 0
    prof = profile.load()
    assert prof.platforms == {"hackerone": "jdoe"}
    assert prof.focus == ["web", "api"] and prof.limits == [] and prof.min_bounty == 1000
    assert prof.chrome_fill is False


def test_capabilities_follow_the_machine():
    bare = machine.Machine(tools=["claude", "node", "npx"], ram_gb=8)
    caps = {c.key: c for c in profile.capabilities(bare, ["iphone"])}
    assert caps["web"].status == "ready"
    assert caps["android"].status == "missing"
    assert caps["ios"].status == "partial"
    assert caps["source"].status == "missing"
    caps = {c.key: c for c in profile.capabilities(LAPTOP, [])}
    assert caps["android"].status == "ready" and caps["source"].status == "ready"


def test_parallel_slots():
    assert LAPTOP.parallel_slots() == 8
    assert machine.Machine(cpus=4, ram_gb=8).parallel_slots() == 1
    assert machine.Machine(cpus=8, ram_gb=16).parallel_slots() == 4


def _profile(**kw) -> profile.Profile:
    base = dict(platforms={"hackerone": "jdoe"}, devices=["android"], focus=["web", "api", "mobile"])
    return profile.Profile(**{**base, "machine": vars(LAPTOP), "timezone": "UTC+01:00", **kw})


def test_fit_profile_replaces_only_the_example(tmp_path):
    from bountyproof.assets import assets_root

    rubric = (assets_root() / "radar" / "fit-score.md").read_text(encoding="utf-8")
    filled = profile.with_fit_profile(rubric, _profile(limits=["corporate-email"], min_bounty=750))
    section = filled.split("## Your hunter profile")[1].split("\n---\n")[0]
    assert "one Android phone" in section and "750" in section and "corporate" in section
    assert "multi-step checkout logic" not in section  # the example profile is gone
    assert filled.split("\n---\n", 2)[2] == rubric.split("\n---\n", 2)[2]  # the rubric itself is untouched


def test_new_workspace_gets_profile_folder_and_notes(laptop, tmp_path):
    profile.save(_profile(workspaces_dir=str(tmp_path / "bounties")))
    assert cli.main(["new", "Acme", "--no-git"]) == 0
    ws = tmp_path / "bounties" / "acme-hackerone"  # the only platform in the profile
    notes = (ws / "notes" / "hunter-profile.md").read_text(encoding="utf-8")
    assert "HackerOne: `jdoe`" in notes and "| Android apps | ready |" in notes
    assert "- Fill with Claude in Chrome: on" in notes  # the default


def test_chrome_form_fill_is_on_by_default_and_can_be_turned_off(laptop, tmp_path, capsys):
    cli.main(["onboard", "--yes", "--platform", "none", "--workspaces", str(tmp_path)])
    assert profile.load().chrome_fill is True
    assert "fill the platform's form" in capsys.readouterr().out
    cli.main(["onboard", "--yes", "--platform", "none", "--no-chrome-fill", "--workspaces", str(tmp_path)])
    prof = profile.load()
    assert prof.chrome_fill is False
    assert "- Fill with Claude in Chrome: off" in profile.hunter_notes(prof)


def test_radar_write_only_watches_your_platforms(tmp_path):
    dest = tmp_path / "radar"
    watched = radar.write(dest, _profile(platforms={"intigriti": "x"}))
    assert watched == ["intigriti"]
    assert [p.name for p in (dest / ".github" / "workflows").iterdir()] == ["radar-intigriti.yml"]
    assert "one Android phone" in (dest / "radar" / "fit-score.md").read_text(encoding="utf-8")
    assert radar.needed_secrets(watched) == ["INTIGRITI_TOKEN", "ANTHROPIC_API_KEY"]
    with pytest.raises(radar.RadarError):
        radar.write(dest, _profile())
    assert radar.platforms_for(_profile(platforms={})) == ["ywh"]  # public listing, no account needed


def test_radar_setup_on_github(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, cwd=None, stdin=None, check=True):
        calls.append((cmd, stdin))
        out = "jdoe/bountyproof-radar\n" if cmd[:3] == ["gh", "repo", "view"] else ""
        return type("Done", (), {"returncode": 0, "stdout": out, "stderr": ""})()

    monkeypatch.setattr(radar, "_run", fake_run)
    monkeypatch.setattr(radar, "gh_ready", lambda: True)
    prof = radar.setup(
        _profile(platforms={"hackerone": "jdoe", "ywh": ""}),
        tmp_path / "radar",
        ask=lambda _: "",
        secret=lambda prompt: "tok-123" if "API token" in prompt else "",
    )
    assert prof.radar["repo"] == "jdoe/bountyproof-radar"
    secrets = {cmd[3]: value for cmd, value in calls if cmd[:3] == ["gh", "secret", "set"]}
    assert secrets["H1_USERNAME"] == "jdoe" and secrets["H1_TOKEN"] == "tok-123"
    assert secrets["NTFY_TOPIC"] == prof.radar["ntfy_topic"] and "ANTHROPIC_API_KEY" not in secrets
    runs = [cmd for cmd, _ in calls if cmd[:3] == ["gh", "workflow", "run"]]
    assert [r[3] for r in runs] == ["radar-yeswehack.yml", "radar-hackerone.yml", "radar-yeswehack.yml"]
    assert runs[-1][-2:] == ["-f", "test_alert=true"]
    assert all("tok-123" not in " ".join(cmd) for cmd, _ in calls)  # tokens only ever go through stdin


def test_skipped_token_turns_that_platform_off(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, cwd=None, stdin=None, check=True):
        calls.append(cmd)
        return type("Done", (), {"returncode": 0, "stdout": "jdoe/r\n", "stderr": ""})()

    monkeypatch.setattr(radar, "_run", fake_run)
    monkeypatch.setattr(radar, "gh_ready", lambda: True)
    radar.setup(_profile(platforms={"intigriti": ""}), tmp_path / "r", ask=lambda _: "", secret=lambda _: "")
    assert ["gh", "workflow", "disable", "radar-intigriti.yml", "--repo", "jdoe/r"] in calls
    assert not [c for c in calls if c[:3] == ["gh", "workflow", "run"]]


def test_profile_file_is_plain_json(laptop, tmp_path):
    cli.main(["onboard", "--yes", "--platform", "none", "--device", "none", "--workspaces", str(tmp_path)])
    data = json.loads(profile.path().read_text(encoding="utf-8"))
    assert data["platforms"] == {} and data["devices"] == [] and data["version"] == 1
    assert onboard.default_focus(LAPTOP, []) == ["web", "api", "mobile", "source"]
