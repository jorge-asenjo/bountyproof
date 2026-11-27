"""bountyproof scope import: a program's published scope -> notes/scope.json, enforced by the hook.

Every fixture is synthetic (example.com and RFC 5737 / 3849 addresses) but shaped like the
bounty-targets-data records the importer reads.
"""

import io
import json

import pytest
from conftest import needs_node

from bountyproof import cli, scope
from bountyproof import scope_import as si


def h1(identifier, asset_type, submit=True, **extra):
    return {"asset_identifier": identifier, "asset_type": asset_type, "eligible_for_submission": submit, **extra}


H1_RECORD = {
    "handle": "acme",
    "name": "Acme",
    "url": "https://hackerone.com/acme",
    "submission_state": "open",
    "targets": {
        "in_scope": [
            h1("app.example.com", "URL", eligible_for_bounty=True, max_severity="critical", instruction="Main app"),
            h1("*.api.example.com", "WILDCARD"),
            h1("https://portal.example.org:8443/", "URL"),
            h1("https://docs.example.net/v2/reference", "API"),
            h1("https://v1.api.example.com/status", "API"),
            h1("203.0.113.0/28", "CIDR"),
            h1("com.example.mobile", "GOOGLE_PLAY_APP_ID"),
            h1("<your-tenant>.example.com", "URL"),
        ],
        "out_of_scope": [
            h1("legacy.api.example.com", "URL", submit=False),
            h1("https://app.example.com/blog", "URL", submit=False),
        ],
    },
}


def program(record=H1_RECORD, platform="hackerone"):
    p = si.program_from_record(platform, record)
    p.source = "test dump"
    return p


def imported(ws, record=H1_RECORD, platform="hackerone", confirm=True):
    """Import into the workspace's scope.json, as `bountyproof scope import` does, and confirm it."""
    path = ws / "notes" / "scope.json"
    res = si.apply(scope.load(path), program(record, platform), whitebox=si.is_whitebox(ws))
    scope.save(path, res.scope)
    if confirm:
        scope.confirm(path, scope.load(path))
    return res


# ---------------------------------------------------------------- one asset -> a rule, or not


@pytest.mark.parametrize(
    ("raw", "typ", "side", "rules"),
    [
        ("app.example.com", "URL", "in", ["app.example.com"]),  # exact: only that host
        ("https://App.Example.com:8443/", "URL", "in", ["app.example.com"]),
        ("*.example.com", "WILDCARD", "in", ["*.example.com"]),
        ("http://*.example.com/*", "WILDCARD", "in", ["*.example.com"]),
        ("203.0.113.7:8443", "IP_ADDRESS", "in", ["203.0.113.7"]),
        ("203.0.113.0/24", "CIDR", "in", ["203.0.113.0/24"]),
        ("2001:DB8::/48", "CIDR", "in", ["2001:db8::/48"]),
        ("198.51.100.0 - 198.51.100.255", "iprange", "in", ["198.51.100.0/24"]),
        ("198.51.100.0-95", "iprange", "in", ["198.51.100.0/26", "198.51.100.64/27"]),
        ("*.example.{com,net}", "WILDCARD", "in", ["*.example.com", "*.example.net"]),
        ("a.example.com, b.example.com", "URL", "in", ["a.example.com", "b.example.com"]),
        ("bücher.example", "URL", "in", ["xn--bcher-kva.example"]),  # IDN -> punycode
        ("www.*.example.*.com", "WILDCARD", "out", ["www.*.example.*.com"]),  # a deny pattern
        ("staging.example.com", "other", "out", ["staging.example.com"]),  # untyped, still denied
        ("billing.example.com - legacy billing", "other", "out", ["billing.example.com"]),  # their #235
        ("**vpn.example.com**", "", "out", ["vpn.example.com"]),  # emphasis, their #235
    ],
)
def test_assets_that_become_rules(raw, typ, side, rules):
    e = si.classify(raw, typ, side)
    assert (e.status, e.rules) == ("rule", rules), e
    for rule in rules:  # the hook reads every rule exactly as written
        assert scope.canon_rule(rule, side).rule.text == rule


@pytest.mark.parametrize(
    ("raw", "typ"),
    [
        ("<your-tenant>.example.com", "URL"),
        ("app[.staging].example.com", "website"),
        ("All APIs used by the mobile app", "API"),
        ("www.*.example.com", "WILDCARD"),  # mid-label wildcard on the in-scope side
        ("*.example.com,uk,co.uk", "WILDCARD"),
        ("co.uk", "URL"),
        ("*.co.uk", "WILDCARD"),
        ("faß.example", "URL"),  # curl and browsers encode ß differently
        ("https://api.example.com/v1/users", "API"),  # path-limited
        ("██████", "URL"),  # redacted in the public data
        ("", "URL"),
    ],
)
def test_ambiguous_assets_go_to_review_never_to_rules(raw, typ):
    e = si.classify(raw, typ, "in")
    assert (e.status, e.rules) == ("review", []), e
    assert e.reason


def test_a_path_limited_asset_suggests_its_host_and_an_excluded_path_is_listed():
    e = si.classify("https://api.example.com/v1/users", "API", "in")
    assert e.suggest == "api.example.com" and "/v1/users" in e.reason
    e = si.classify("https://app.example.com/blog", "URL", "out")
    assert (e.status, e.rules) == ("review", []) and "do not test /blog" in e.reason


@pytest.mark.parametrize(
    ("raw", "typ", "side"),
    [("com.example.mobile", "GOOGLE_PLAY_APP_ID", "in"), ("com.example.mobile", "GOOGLE_PLAY_APP_ID", "out"),
     ("github.com/example/repo", "SOURCE_CODE", "in"), ("app.example.com", "ios", "out")],
)  # fmt: skip
def test_non_host_assets_are_never_rules(raw, typ, side):
    assert si.classify(raw, typ, side).status == "other"


# ---------------------------------------------------------------- whole programs


def test_hackerone_record():
    p = program()
    assert p.rules("in") == ["app.example.com", "*.api.example.com", "portal.example.org", "203.0.113.0/28"]
    assert p.rules("out") == ["legacy.api.example.com"]
    review = {item["asset"] for item in p.review()}
    assert review == {
        "https://docs.example.net/v2/reference",
        "<your-tenant>.example.com",
        "https://app.example.com/blog",
    }
    assert "https://v1.api.example.com/status" not in review  # covered by *.api.example.com
    assert [o["asset"] for o in p.other()] == ["com.example.mobile"]


def test_bugcrowd_intigriti_and_yeswehack_records():
    bc = {"name": "Acme", "url": "https://bugcrowd.com/engagements/acme-mbb", "targets": {
        "in_scope": [{"type": "website", "target": "https://www.example.com/", "name": "Website"},
                     {"type": "api", "target": "api.example.com (REST)"},
                     {"type": "android", "target": "com.example.app"}],
        "out_of_scope": [{"type": "other", "target": "Any third-party service"},
                         {"type": "website", "target": "shop.example.com"}]}}  # fmt: skip
    p = program(bc, "bugcrowd")
    assert p.handle == "acme-mbb"
    assert (p.rules("in"), p.rules("out")) == (["www.example.com", "api.example.com"], ["shop.example.com"])

    it = {"handle": "acmebbp", "company_handle": "acme", "name": "Acme BBP", "targets": {
        "in_scope": [{"type": "wildcard", "endpoint": "*.example.com", "impact": "Tier 1"},
                     {"type": "iprange", "endpoint": "198.51.100.0 - 198.51.100.127", "impact": "No Bounty"}],
        "out_of_scope": [{"type": "url", "endpoint": "status.example.com", "impact": "Out of scope"}]}}  # fmt: skip
    p = program(it, "intigriti")
    assert p.handle == "acme/acmebbp"
    assert (p.rules("in"), p.rules("out")) == (["*.example.com", "198.51.100.0/25"], ["status.example.com"])

    ywh = {"id": "acme", "name": "Acme", "targets": {
        "in_scope": [{"target": "https://app.example.com", "type": "web-application"},
                     {"target": "Any resource created in your account", "type": "other"}],
        "out_of_scope": [{"target": "blog.example.com", "type": "other"}]}}  # fmt: skip
    p = program(ywh, "yeswehack")
    assert (p.rules("in"), p.rules("out")) == (["app.example.com"], ["blog.example.com"])


TEXT = """Acme program

Keep automated scanning under 5 requests per second.
Use your platform email alias for test accounts.

In Scope (3)
| Type | Asset | Max severity |
|---|---|---|
| Wildcard | *.example.com | Critical |
| API | https://api.example.net/v2 | High |
| CIDR | 192.0.2.0/28 | Low |

Out of scope
- admin.example.com
- **vpn.example.com**
- billing.example.com - legacy billing
- Clickjacking on pages without sensitive actions

Rewards
- Critical: $5,000
- partner.example.org
"""


def test_pasted_text_in_either_column_order():
    p = si.program_from_text(TEXT, name="acme")
    assert p.rules("in") == ["*.example.com", "192.0.2.0/28"]
    # every excluded host is denied, however the page wrote it (their #235)
    assert p.rules("out") == ["admin.example.com", "vpn.example.com", "billing.example.com"]
    assert p.exclusions == ["Clickjacking on pages without sensitive actions"]
    assert [item["asset"] for item in p.review()] == ["https://api.example.net/v2"]
    assert "partner.example.org" not in p.rules("in") + p.rules("out")  # after "Rewards"
    assert [c.split(":", 1)[0] for c in p.conduct] == ["rate limit", "test account"]


def test_a_markdown_heading_ends_a_list():
    p = si.program_from_text("## In scope\n- a.example.com\n## Bounties\n- b.example.com\n")
    assert p.rules("in") == ["a.example.com"]


# ---------------------------------------------------------------- into the workspace, through the hook


@needs_node
def test_the_hook_admits_the_declared_assets_and_nothing_more(make_ws):
    ws = make_ws()  # black-box: requireConfirm
    imported(ws)
    data = scope.load(ws / "notes" / "scope.json")
    compiled = scope.compile_scope(data)
    assert compiled.errors == []
    cases = {
        "https://app.example.com/login": "allow",
        "https://v2.api.example.com/": "allow",
        "https://portal.example.org/": "allow",
        "http://203.0.113.9/": "allow",
        "https://admin.app.example.com/": "deny",  # an exact host has no subdomains
        "https://example.com/": "deny",  # the apex is never implied
        "https://legacy.api.example.com/": "deny",  # out of scope wins over the wildcard
        "https://docs.example.net/": "deny",  # path-limited: review only
        "https://tenant.example.com/": "deny",  # placeholder: review only
    }
    data["uaTag"] = ""
    scope.save(ws / "notes" / "scope.json", data)
    for url, want in cases.items():
        assert scope.check(ws, url).decision == want, url
        host = scope.canon_host(url).host  # and the CLI classifies the same way
        assert (scope.classify(host, compiled) == "IN_SCOPE") == (want == "allow"), url


@needs_node
def test_hosts_found_by_recon_stay_out(make_ws):
    """Recon finds subdomains, siblings and the apex of exact hosts: none of them enters the scope."""
    ws = make_ws()
    (ws / "notes" / "attack-surface.md").write_text(
        "## Live hosts (recon)\n- dev.app.example.com\n- jira.example.com\n- example.org\n", encoding="utf-8"
    )
    res = imported(ws)
    for host in ("dev.app.example.com", "jira.example.com", "example.org"):
        assert host not in res.scope["inScope"]
        assert scope.check(ws, f"https://{host}/").decision == "deny", host
    again = si.apply(res.scope, program())  # re-importing doesn't pick them up either
    assert again.scope["inScope"] == res.scope["inScope"]


def test_reimport_refreshes_imported_rules_and_keeps_the_hand_written_ones(make_ws):
    ws = make_ws()
    path = ws / "notes" / "scope.json"
    data = scope.load(path)
    data["inScope"] = ["manual.example.com"]
    data["outOfScope"] = ["manual-oos.example.com"]
    first = si.apply(data, program())
    assert first.kept_in == ["manual.example.com"] and first.kept_out == ["manual-oos.example.com"]
    assert si.apply(first.scope, program()).scope == first.scope  # idempotent
    smaller = {**H1_RECORD, "targets": {"in_scope": H1_RECORD["targets"]["in_scope"][:1], "out_of_scope": []}}
    second = si.apply(first.scope, program(smaller))
    assert second.scope["inScope"] == ["app.example.com", "manual.example.com"]
    assert second.scope["outOfScope"] == ["manual-oos.example.com"]
    assert second.scope["needsReview"] == []


def test_a_hand_rule_the_program_excludes_is_reported():
    res = si.apply({"inScope": ["legacy.api.example.com"]}, program())
    assert res.conflicts == ["legacy.api.example.com"]


def test_whitebox_puts_every_program_asset_out_of_scope(make_ws):
    ws = make_ws("whitebox")
    path = ws / "notes" / "scope.json"
    data = scope.load(path)
    data["inScope"] = ["localhost", "127.0.0.1"]
    scope.save(path, data)
    res = imported(ws, confirm=False)
    assert res.whitebox
    assert res.scope["inScope"] == ["localhost", "127.0.0.1"]
    assert "app.example.com" in res.scope["outOfScope"] and "*.api.example.com" in res.scope["outOfScope"]


@needs_node
def test_importing_changes_the_hash_so_the_human_confirms_again(make_ws):
    ws = make_ws(uaTag="")
    path = ws / "notes" / "scope.json"
    data = scope.load(path)
    data["inScope"] = ["app.example.com"]
    scope.save(path, data)
    scope.confirm(path, scope.load(path))
    assert scope.check(ws, "https://app.example.com/").decision == "allow"
    res = imported(ws, confirm=False)
    assert res.changed
    assert scope.check(ws, "https://app.example.com/").decision == "deny"  # stale confirmation
    scope.confirm(path, scope.load(path))
    assert scope.check(ws, "https://app.example.com/").decision == "allow"


# ---------------------------------------------------------------- the command


def run(argv, monkeypatch, cwd, capsys, stdin=None):
    monkeypatch.chdir(cwd)
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_import_from_a_local_dump(make_ws, tmp_path, monkeypatch, capsys):
    ws = make_ws()
    dump = tmp_path / "hackerone_data.json"
    dump.write_text(json.dumps([H1_RECORD]), encoding="utf-8")
    before = (ws / "notes" / "scope.json").read_text(encoding="utf-8")
    code, out, _ = run(["scope", "import", "h1:acme", "--data", str(dump), "--dry-run"], monkeypatch, ws, capsys)
    assert code == 0 and "Dry run" in out
    assert (ws / "notes" / "scope.json").read_text(encoding="utf-8") == before
    code, out, _ = run(["scope", "import", "https://hackerone.com/acme", "--data", str(dump)], monkeypatch, ws, capsys)
    assert code == 0
    assert "4 rules" in out and "1 rule " in out and "needs review   3" in out and "bountyproof scope confirm" in out
    data = scope.load(ws / "notes" / "scope.json")
    assert data["_import"]["program"] == "hackerone:acme"
    assert not scope.is_confirmed(data)


def test_cli_import_from_pasted_text(make_ws, monkeypatch, capsys):
    ws = make_ws()
    code, out, _ = run(["scope", "import", "--text", "-", "--name", "acme"], monkeypatch, ws, capsys, stdin=TEXT)
    assert code == 0 and "rate limit" in out
    assert scope.load(ws / "notes" / "scope.json")["outOfScope"] == ["admin.example.com", "vpn.example.com",
                                                                    "billing.example.com"]  # fmt: skip


def test_cli_import_errors(make_ws, monkeypatch, capsys):
    ws = make_ws()
    assert run(["scope", "import"], monkeypatch, ws, capsys)[0] == 2
    assert run(["scope", "import", "h1:a", "--text", "x"], monkeypatch, ws, capsys)[0] == 2
    code, _, err = run(["scope", "import", "nope"], monkeypatch, ws, capsys)
    assert code == 1 and "program reference" in err


def test_confirm_shows_what_needs_review(make_ws, monkeypatch, capsys):
    ws = make_ws()
    imported(ws, confirm=False)
    code, out, _ = run(["scope", "confirm", "--yes"], monkeypatch, ws, capsys)
    assert code == 0 and "NEEDS REVIEW" in out and "<your-tenant>.example.com" in out


def test_confirm_refuses_a_scope_the_guard_cant_enforce(make_ws, monkeypatch, capsys):
    ws = make_ws(inScope=["app.example.com", "*.co.uk"])
    code, out, _ = run(["scope", "confirm", "--yes"], monkeypatch, ws, capsys)
    assert code == 1 and "*.co.uk" in out
    assert not scope.is_confirmed(scope.load(ws / "notes" / "scope.json"))


# ---------------------------------------------------------------- references and bounty-targets-data


def test_parse_ref():
    cases = {
        "h1:acme": ("hackerone", "acme"),
        "ywh:acme-bbp": ("yeswehack", "acme-bbp"),
        "https://hackerone.com/acme?type=team": ("hackerone", "acme"),
        "https://bugcrowd.com/engagements/acme-mbb": ("bugcrowd", "acme-mbb"),
        "https://app.intigriti.com/programs/acme/acmebbp/detail": ("intigriti", "acme/acmebbp"),
        "https://yeswehack.com/programs/acme": ("yeswehack", "acme"),
    }
    for ref, want in cases.items():
        assert si.parse_ref(ref) == want, ref
    for bad in ("acme", "gitlab:acme", "https://example.com/acme", "h1:"):
        with pytest.raises(ValueError):
            si.parse_ref(bad)


def test_find_program_with_suggestions_and_a_company_with_two_programs():
    data = [H1_RECORD, {**H1_RECORD, "handle": "acme_vdp", "url": "https://hackerone.com/acme_vdp"}]
    assert si.find_program("hackerone", data, "ACME") is H1_RECORD
    with pytest.raises(LookupError, match="acme_vdp"):
        si.find_program("hackerone", data, "acme_vpd")
    a = {"handle": "acmebbp", "company_handle": "acme", "url": "u1", "targets": {}}
    b = {"handle": "acmevdp", "company_handle": "acme", "url": "u2", "targets": {}}
    assert si.find_program("intigriti", [a, b], "acme/acmevdp") is b
    with pytest.raises(LookupError):
        si.find_program("intigriti", [a, b], "acme")


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_download_cache_and_fallback(tmp_path):
    calls = []

    def opener(body):
        def _open(req, timeout):
            calls.append(req.full_url)
            assert req.get_header("User-agent") == si.USER_AGENT
            if isinstance(body, Exception):
                raise body
            return _Resp(body)

        return _open

    data, _ = si.load_platform("hackerone", cache=tmp_path, opener=opener(json.dumps([H1_RECORD]).encode()))
    assert data[0]["handle"] == "acme" and calls[0].endswith("/hackerone_data.json")
    si.load_platform("hackerone", cache=tmp_path, opener=opener(b"[]"))
    assert len(calls) == 1  # fresh cache: no request
    logs = []
    data, _ = si.load_platform(
        "hackerone", refresh=True, cache=tmp_path, opener=opener(b"<html>rate limited"), log=logs.append
    )
    assert data[0]["handle"] == "acme" and "using the cached" in logs[0]  # junk is never cached
    with pytest.raises(si.ScopeImportError):
        si.load_platform("intigriti", cache=tmp_path, opener=opener(OSError("offline")))


def test_the_cache_lives_outside_the_workspace(bountyproof_home):
    assert si.cache_dir().is_relative_to(bountyproof_home)


def test_an_excluded_wildcard_over_listed_hosts_means_everything_else():
    """'In scope: app.example.com. Out of scope: *.example.com' means every OTHER example.com host."""
    rec = {"handle": "acme", "targets": {
        "in_scope": [h1("app.example.com", "URL"), h1("*.api.example.com", "WILDCARD")],
        "out_of_scope": [h1("*.example.com", "WILDCARD", submit=False),
                         h1("legacy.api.example.com", "URL", submit=False),
                         h1("*.other.test", "WILDCARD", submit=False)]}}  # fmt: skip
    res = si.apply({}, program(rec))
    assert res.scope["denyUnlisted"] == ["*.example.com"]
    assert res.scope["outOfScope"] == ["legacy.api.example.com", "*.other.test"]
    c = scope.compile_scope(res.scope)
    assert scope.classify("app.example.com", c) == "IN_SCOPE"
    assert scope.classify("v1.api.example.com", c) == "IN_SCOPE"
    assert scope.classify("legacy.api.example.com", c) == "OOS"  # an exact exclusion still wins
    assert scope.classify("shop.example.com", c) == "OOS_UNLISTED"
    again = si.apply(res.scope, program({**rec, "targets": {**rec["targets"], "out_of_scope": []}}))
    assert again.scope["denyUnlisted"] == []  # imported, so a re-import refreshes it
