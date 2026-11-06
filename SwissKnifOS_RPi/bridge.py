"""Nonblocking process bridge between the LCD UI and existing CLI modules."""

from __future__ import annotations

import codecs
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from typing import Literal


Event = tuple[Literal["text", "input"], str | bool]
_ROOT = Path(__file__).resolve().parent.parent
_RUNNER = Path(__file__).resolve().with_name("runner.py")


class ModuleProcess:
    """Run one module and report output and input requests to the LCD UI.

    Call ``poll`` regularly from the UI loop.  An ``('input', True)`` event
    requests a concealed value; ``send`` submits one line for either kind of
    input request.  ``interrupt`` is the equivalent of Ctrl+C.
    """

    def __init__(self, script: Path, args: list[str] | None = None) -> None:
        self.script = Path(script).resolve()
        self.args = list(args or [])
        self._process: subprocess.Popen[bytes] | None = None
        self._selector = selectors.DefaultSelector()
        self._control_fd: int | None = None
        self._control_buffer = bytearray()
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._closed = False

    @property
    def returncode(self) -> int | None:
        return self._process.poll() if self._process is not None else None

    def start(self) -> None:
        if self._process is not None:
            raise RuntimeError("module already started")
        if not self.script.is_file():
            raise FileNotFoundError(self.script)

        read_fd, write_fd = os.pipe()
        env = os.environ.copy()
        env.update(
            SWISSKNIFE_CONTROL_FD=str(write_fd),
            PYTHONUNBUFFERED="1",
            PYTHONIOENCODING="utf-8:replace",
            SWISSKNIFOS_LCD="1",
            TERM="dumb",
            NO_COLOR="1",
            CLICOLOR="0",
            FORCE_COLOR="0",
        )
        try:
            self._process = subprocess.Popen(
                [sys.executable, "-u", str(_RUNNER), str(self.script), *self.args],
                cwd=_ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                pass_fds=(write_fd,),
                start_new_session=True,
            )
        except BaseException:
            os.close(read_fd)
            raise
        finally:
            os.close(write_fd)

        assert self._process.stdout is not None
        self._control_fd = read_fd
        os.set_blocking(read_fd, False)
        os.set_blocking(self._process.stdout.fileno(), False)
        self._selector.register(self._process.stdout, selectors.EVENT_READ, "stdout")
        self._selector.register(read_fd, selectors.EVENT_READ, "control")

    def poll(self) -> list[Event]:
        """Return currently available events without waiting for the module."""
        if self._process is None or self._closed:
            return []

        events: list[Event] = []
        ready = self._selector.select(timeout=0)
        # Input prompts are written to stdout before the control message.
        # Read stdout first when both pipes have data in the same UI frame.
        ready.sort(key=lambda pair: pair[0].data != "stdout")
        for key, _ in ready:
            try:
                chunk = os.read(key.fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                self._selector.unregister(key.fileobj)
                if key.data == "stdout":
                    tail = self._decoder.decode(b"", final=True)
                    if tail:
                        events.append(("text", tail))
                    key.fileobj.close()
                else:
                    os.close(key.fd)
                    self._control_fd = None
                continue

            if key.data == "stdout":
                rendered = self._decoder.decode(chunk)
                if rendered:
                    events.append(("text", rendered))
            else:
                self._control_buffer.extend(chunk)
                while b"\n" in self._control_buffer:
                    raw, _, remaining = self._control_buffer.partition(b"\n")
                    self._control_buffer = bytearray(remaining)
                    try:
                        message = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if message.get("type") == "input":
                        events.append(("input", bool(message.get("secret", False))))

        self._process.poll()
        return events

    def send(self, value: str) -> None:
        """Submit one line to the module's pending prompt."""
        if "\n" in value or "\r" in value:
            raise ValueError("input must contain one line")
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("module is not running")
        assert self._process.stdin is not None
        try:
            self._process.stdin.write((value + "\n").encode("utf-8"))
            self._process.stdin.flush()
        except BrokenPipeError as exc:
            raise RuntimeError("module stopped before receiving input") from exc

    def interrupt(self) -> None:
        """Ask the module and its child processes to stop, like Ctrl+C."""
        if self._process is not None and self._process.poll() is None:
            try:
                os.killpg(self._process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass

    def terminate(self) -> None:
        """Stop the process group, escalating if cleanup takes too long."""
        process = self._process
        if process is None or self._closed:
            return
        if process.poll() is None:
            # Most existing modules clean up their interfaces and child tools
            # in KeyboardInterrupt handlers, so give that path a chance first.
            try:
                os.killpg(process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 1.5
            while process.poll() is None and time.monotonic() < deadline:
                self.poll()  # Prevent a full output pipe from blocking cleanup.
                time.sleep(0.02)
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 0.5
                while process.poll() is None and time.monotonic() < deadline:
                    self.poll()
                    time.sleep(0.02)
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        process.wait()
        self.poll()
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        if self._control_fd is not None:
            os.close(self._control_fd)
            self._control_fd = None
        self._selector.close()
        self._closed = True

