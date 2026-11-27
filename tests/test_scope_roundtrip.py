"""scripts/scope_roundtrip.py on a tiny synthetic dump, so the weekly check doesn't rot.

The real run (every public program in bounty-targets-data) is outside CI: it needs the network."""

import importlib.util
import json
from pathlib import Path

from conftest import needs_node
from test_scope_import import H1_RECORD

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "scope_roundtrip.py"


def load_script():
    spec = importlib.util.spec_from_file_location("scope_roundtrip", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dumps(tmp_path: Path) -> Path:
    data = {
        "hackerone": [H1_RECORD],
        "bugcrowd": [{"name": "B", "url": "https://bugcrowd.com/engagements/b", "targets": {
            "in_scope": [{"type": "website", "target": "www.example.com"}],
            "out_of_scope": [{"type": "website", "target": "*.example.com"}]}}],
        "intigriti": [{"handle": "i", "company_handle": "c", "targets": {
            "in_scope": [{"type": "wildcard", "endpoint": "*.example.org", "impact": "Tier 1"}], "out_of_scope": []}}],
        "yeswehack": [{"id": "y", "targets": {
            "in_scope": [{"target": "https://app.example.net", "type": "web-application"}], "out_of_scope": []}}],
    }  # fmt: skip
    for platform, records in data.items():
        (tmp_path / f"{platform}_data.json").write_text(json.dumps(records), encoding="utf-8")
    return tmp_path


@needs_node
def test_roundtrip_passes_on_synthetic_dumps(tmp_path, capsys):
    assert load_script().main(["--data", str(dumps(tmp_path))]) == 0
    assert "Node and Python agree" in capsys.readouterr().out


def test_roundtrip_reports_a_subdomain_that_gets_in(tmp_path, capsys, monkeypatch):
    module = load_script()
    real = module.scope.classify
    monkeypatch.setattr(module.scope, "classify", lambda host, c: "IN_SCOPE" if "probe" in host else real(host, c))
    assert module.main(["--data", str(dumps(tmp_path)), "--no-node"]) == 1
    assert "zz-roundtrip-probe.app.example.com is IN_SCOPE" in capsys.readouterr().out
