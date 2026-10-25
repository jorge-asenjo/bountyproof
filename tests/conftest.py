import json
import shutil
from pathlib import Path

import pytest

from bountyproof import workspace

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")


@pytest.fixture
def make_ws(tmp_path: Path):
    """Create a workspace and optionally fill its scope."""

    def _make(mode: str = "blackbox", platform: str = "hackerone", **scope_fields) -> Path:
        ws = workspace.create(workspace.Engagement("Acme Corp", platform, mode), tmp_path, init_git=False)
        if scope_fields:
            path = ws / "notes" / "scope.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data.update(scope_fields)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return ws

    return _make


SCOPE = {
    "inScope": ["app.example.com", "*.api.example.com"],
    "outOfScope": ["admin.example.com"],
    "denyUnlisted": ["example.com", "*.example.com"],
    "uaTag": "BugBounty-tester",
}
