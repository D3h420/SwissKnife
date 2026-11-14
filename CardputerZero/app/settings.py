"""Per-user Cardputer display preferences and idle timing."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path


SCREEN_TIMEOUTS = (
    ("Never", 0),
    ("30 seconds", 30),
    ("1 minute", 60),
    ("2 minutes", 120),
    ("5 minutes", 300),
    ("10 minutes", 600),
)
VALID_TIMEOUTS = frozenset(seconds for _label, seconds in SCREEN_TIMEOUTS)


def settings_path() -> Path:
    state = os.environ.get("SWISSKNIFE_DATA_DIR")
    if state:
        return Path(state).expanduser() / "cardputer-settings.json"
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))).expanduser() / "swissknife" / "cardputer-settings.json"


def load_screen_timeout(path: Path) -> int:
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get("screen_timeout_seconds", 0)
        return value if type(value) is int and value in VALID_TIMEOUTS else 0
    except (OSError, ValueError, TypeError, AttributeError):
        return 0


def save_screen_timeout(path: Path, seconds: int) -> None:
    if type(seconds) is not int or seconds not in VALID_TIMEOUTS:
        raise ValueError("Unsupported screen timeout")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".cardputer-settings-", delete=False) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump({"screen_timeout_seconds": seconds}, handle)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class IdleScreen:
    def __init__(self) -> None:
        self.last_activity = time.monotonic()
        self.blanked = False

    def key_pressed(self, now: float | None = None) -> bool:
        """Return True when this key only wakes the screen."""
        self.last_activity = time.monotonic() if now is None else now
        if self.blanked:
            self.blanked = False
            return True
        return False

    def should_blank(self, timeout_seconds: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if timeout_seconds > 0 and not self.blanked and now - self.last_activity >= timeout_seconds:
            self.blanked = True
            return True
        return False
