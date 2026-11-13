"""Run a SwissKnife CLI module with its input requests on a separate pipe.

The graphical application cannot infer from terminal output when a module is waiting
for text.  This process intercepts the input functions used by the existing
modules and announces each blocking read on ``SWISSKNIFE_CONTROL_FD``.  The
module's normal output stays on stdout/stderr for display in the GUI.
"""

from __future__ import annotations

import builtins
import getpass
import json
import os
from pathlib import Path
import runpy
import sys
import threading
from typing import TextIO


_input_lock = threading.Lock()
_raw_stdin = sys.stdin


def _request_input(secret: bool, size: int = -1) -> str:
    """Tell the UI about a pending read, then consume one submitted line."""
    with _input_lock:
        control_fd = int(os.environ["SWISSKNIFE_CONTROL_FD"])
        prefix = os.environ.get("SWISSKNIFE_CONTROL_PREFIX", "")
        message = prefix + json.dumps({"type": "input", "secret": secret}) + "\n"
        os.write(control_fd, message.encode("utf-8"))
        return _raw_stdin.readline(size)


def _input(prompt: object = "") -> str:
    sys.stdout.write(str(prompt))
    sys.stdout.flush()
    line = _request_input(False)
    if line == "":
        raise EOFError
    return line.rstrip("\r\n")


def _getpass(prompt: str = "Password: ", stream: TextIO | None = None) -> str:
    destination = stream if stream is not None else sys.stderr
    destination.write(prompt)
    destination.flush()
    line = _request_input(True)
    if line == "":
        raise EOFError
    return line.rstrip("\r\n")


class _PromptingStdin:
    """Forward normal stdin operations while intercepting line reads."""

    def __init__(self, wrapped: TextIO) -> None:
        self._wrapped = wrapped

    def readline(self, size: int = -1) -> str:
        return _request_input(False, size)

    def __iter__(self):
        return self

    def __next__(self) -> str:
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def __getattr__(self, name: str):
        return getattr(self._wrapped, name)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: runner.py SCRIPT [ARG ...]")

    script = Path(sys.argv[1]).resolve()
    if not script.is_file():
        raise SystemExit(f"module not found: {script}")

    # Match direct execution of modules/*.py, whose imports use both the
    # module directory and the repository root.
    project_root = Path(__file__).resolve().parent.parent
    sys.path[:0] = [str(script.parent), str(project_root)]
    sys.argv = [str(script), *sys.argv[2:]]
    builtins.input = _input
    getpass.getpass = _getpass
    sys.stdin = _PromptingStdin(_raw_stdin)  # type: ignore[assignment]
    # The Cardputer worker reserves the original stderr pipe for prompt
    # messages.  Ordinary module diagnostics still belong in the output log.
    if os.environ.get("SWISSKNIFE_CONTROL_PREFIX"):
        sys.stderr = sys.stdout

    runpy.run_path(str(script), run_name="__main__")


if __name__ == "__main__":
    main()
