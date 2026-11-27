"""The CLI's side of the parity corpus: tests/scope-parity.test.mjs runs the same cases on the hook."""

import json
from pathlib import Path

import pytest

from bountyproof import scope

CASES = json.loads((Path(__file__).parent / "scope-cases.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(("token", "want"), CASES["hosts"])
def test_host(token, want):
    got = scope.canon_host(token)
    seen = "local" if got.local else None if got.problem else got.host
    assert seen == want, got


@pytest.mark.parametrize(("entry", "side", "want"), CASES["rules"])
def test_rule(entry, side, want):
    got = scope.canon_rule(entry, side)
    seen = None if got.problem else got.rule.text
    assert seen == want, got
    if seen is not None:
        assert scope.canon_rule(seen, side).rule == got.rule  # written back, it reads as the same rule


@pytest.mark.parametrize(("dest", "want"), CASES["classify"]["cases"])
def test_classify(dest, want):
    compiled = scope.compile_scope(CASES["classify"]["scope"])
    assert compiled.errors == []
    host = scope.canon_host(dest).host
    assert host and scope.classify(host, compiled) == want


@pytest.mark.parametrize(("raw", "valid", "active"), CASES["files"])
def test_file(raw, valid, active):
    compiled = scope.compile_scope(raw)
    assert (not compiled.errors) == valid, compiled.errors
    assert compiled.active == active


def test_load_reads_a_scope_saved_with_a_bom(tmp_path):
    path = tmp_path / "scope.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"inScope": ["app.example.com"]}).encode())
    assert scope.load(path)["inScope"] == ["app.example.com"]
