import json

import pytest
from conftest import SCOPE, needs_node

from bountyproof import cli, funnel, scope, workspace


def test_blackbox_workspace_layout(make_ws):
    ws = make_ws("blackbox", "ywh")
    assert ws.name == "acme-corp-ywh"
    claude_md = (ws / "CLAUDE.md").read_text(encoding="utf-8")
    assert "BLACK-BOX" in claude_md and "Acme Corp" in claude_md and "{{" not in claude_md
    assert not (ws / "CLAUDE.blackbox.md").exists() and not (ws / "CLAUDE.whitebox.md").exists()
    assert not (ws / "docker").exists() and not (ws / "source").exists()
    assert (ws / ".claude" / "hooks" / "scope-guard.mjs").is_file()
    assert (ws / "prompts" / "03b-evidence-judge.md").is_file()
    assert "YesWeHack" in (ws / "reference" / "form-reference.md").read_text(encoding="utf-8")
    assert not list((ws / "reference").glob("*-form-reference.md"))


def test_blackbox_needs_human_scope_confirmation(make_ws):
    assert scope.load(make_ws("blackbox") / "notes" / "scope.json")["requireConfirm"] is True
    assert scope.load(make_ws("whitebox", "ywh") / "notes" / "scope.json")["requireConfirm"] is False


def test_whitebox_workspace_layout(make_ws):
    ws = make_ws("whitebox", "hackerone")
    assert "WHITE-BOX" in (ws / "CLAUDE.md").read_text(encoding="utf-8")
    assert (ws / "docker" / "docker-compose.yml").is_file()
    assert (ws / "source").is_dir()


def test_existing_workspace_is_refused(make_ws, tmp_path):
    make_ws()
    with pytest.raises(workspace.WorkspaceError):
        workspace.create(workspace.Engagement("Acme Corp"), tmp_path, init_git=False)


def test_slugify_rejects_empty_names():
    with pytest.raises(workspace.WorkspaceError):
        workspace.slugify("!!!")


def test_inactive_until_scope_is_filled(make_ws):
    ws = make_ws()
    assert scope.check(ws, "https://app.example.com/").decision == "inactive"


@needs_node
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://app.example.com/profile", "allow"),
        ("https://v2.api.example.com/users/1", "allow"),
        ("https://admin.example.com/", "deny"),  # explicitly out of scope
        ("https://shop.example.com/", "deny"),  # unlisted host under denyUnlisted
        ("https://unrelated.example.org/", "deny"),  # unknown host
        ('curl -A "x BugBounty-tester" -H "Host: admin.example.com" https://app.example.com/', "deny"),
    ],
)
def test_scope_decisions(make_ws, target, expected):
    ws = make_ws(**SCOPE)
    assert scope.check(ws, target).decision == expected


@needs_node
def test_missing_ua_tag_is_denied(make_ws):
    ws = make_ws(**SCOPE)
    verdict = scope.check(ws, "https://app.example.com/", ua="")
    assert verdict.decision == "deny" and "UA tag" in verdict.reason


@needs_node
def test_check_is_a_dry_run(make_ws):
    ws = make_ws(**SCOPE)
    scope.check(ws, "https://app.example.com/")
    assert not (ws / "notes" / "egress-log.jsonl").exists()


@needs_node
def test_confirmation_hash_matches_the_hook(make_ws):
    """Python and the Node hook must compute the same scope hash, or confirmation never unblocks."""
    ws = make_ws(**{**SCOPE, "requireConfirm": True})
    assert scope.check(ws, "https://app.example.com/").decision == "deny"  # not confirmed yet

    scope_file = ws / "notes" / "scope.json"
    scope.confirm(scope_file, scope.load(scope_file))
    assert scope.check(ws, "https://app.example.com/").decision == "allow"

    data = scope.load(scope_file)
    data["inScope"].append("new.example.com")  # widening the scope invalidates the confirmation
    scope_file.write_text(json.dumps(data), encoding="utf-8")
    assert scope.check(ws, "https://app.example.com/").decision == "deny"


def test_scope_hash_is_order_and_case_insensitive():
    a = {"inScope": ["B.example.com", "a.example.com"], "outOfScope": [], "denyUnlisted": []}
    b = {"inScope": ["a.example.com", " b.example.com", "a.example.com"]}
    assert scope.scope_hash(a) == scope.scope_hash(b)


CASE_FILE = """
| ID | Class | Shard / artifact | Trust boundary | Confidence | Status |
|----|-------|------------------|----------------|------------|--------|
| H-001 | authz | orders API | tenant | high | ACCEPTED |
| H-002 | authz | invoices API | tenant | med | confirmed |
| H-003 | ssrf | webhooks | egress | low | rejected |
| H-004 | logic | checkout | payment | med | needs_validation |
| H-005 | | | | low/med/high | candidate |

JUDGE H-001: PASS
JUDGE H-002: DISCARD (already obtainable through the export feature)
"""


def test_funnel_counts(tmp_path):
    path = tmp_path / "case-file.md"
    path.write_text(CASE_FILE, encoding="utf-8")
    f = funnel.parse(path)
    assert (f.proposed, f.validated, f.passed, f.submitted, f.accepted) == (4, 2, 1, 1, 1)
    out = funnel.render(f, "acme")
    assert "hypotheses proposed" in out and "needs_validation 1" in out


def test_cli_new_and_funnel(tmp_path, capsys, monkeypatch):
    assert cli.main(["new", "Demo", "--dir", str(tmp_path), "--no-git"]) == 0
    monkeypatch.chdir(tmp_path / "demo-hackerone")
    assert cli.main(["funnel"]) == 0
    assert "Evidence funnel" in capsys.readouterr().out
