"""Locations for persistent SwissKnife data."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_default_data_dir = "/var/lib/swissknife" if PROJECT_ROOT == Path("/opt/SwissKnife") else str(PROJECT_ROOT)
DATA_DIR = Path(os.environ.get("SWISSKNIFE_DATA_DIR", _default_data_dir)).expanduser()
LOG_DIR = Path(os.environ.get("SWISSKNIFE_LOG_DIR", str(DATA_DIR / "log"))).expanduser()
TOOLS_DIR = Path(os.environ.get("SWISSKNIFE_TOOLS_DIR", str(DATA_DIR / "tools"))).expanduser()
