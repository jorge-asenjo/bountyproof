#!/usr/bin/env python3
"""Run the bountyproof CLI straight from a checkout or the Claude Code plugin cache (no install)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from bountyproof.cli import main  # noqa: E402

raise SystemExit(main())
