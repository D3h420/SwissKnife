"""Run an existing terminal workflow behind the Cardputer graphical shell.

The privileged package helper accepts only feature names from core.features.
This adapter keeps its output and prompt protocol off the GUI thread.  It does
not reimplement any of the workflows in modules/.
"""

from __future__ import annotations

import codecs
import json
import os
import selectors
import signal
import subprocess
import threading
import time
from pathlib import Path

from .engine import EngineEvent, Operation


HELPER = Path("/usr/libexec/swissknife-cardputer/run-module")
PROMPT_PREFIX = "SKINPUT:"


class CliOperation(Operation):
    def __init__(self, key: str, *, helper: Path = HELPER, log_path: Path | None = None) -> None:
        super().__init__(key, {}, log_path=log_path)
        self.helper = helper
        self.awaiting_input = False
        self.secret = False
        self._process: subprocess.Popen[bytes] | None = None
        self._process_lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def send(self, value: str) -> None:
        """Submit a single response to the current CLI prompt."""
        if "\r" in value or "\n" in value or len(value) > 4096:
            raise ValueError("Input must be one line of at most 4096 characters")
        with self._process_lock:
            process = self._process
            if not self.awaiting_input or process is None or process.poll() is not None:
                raise RuntimeError("Module is not waiting for input")
            assert process.stdin is not None
            try:
                process.stdin.write((value + "\n").encode("utf-8"))
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise RuntimeError("Module stopped before receiving input") from exc
            self.awaiting_input = False
            self.secret = False
        self.emit("status", "Answer submitted")

    def cancel(self) -> None:
        if self.cancelled.is_set():
            return
        super().cancel()
        with self._process_lock:
            process = self._process
        if process is not None and process.poll() is None:
            # sudo's monitor forwards SIGINT to the root command.  Signal its
            # own PID rather than a mixed-ownership process group.
            try:
                process.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass

    def _read_control(self, line: str) -> None:
        marker = line.find(PROMPT_PREFIX)
        if marker < 0:
            if line:
                self.emit("output", line + "\n")
            return
        if marker:
            self.emit("output", line[:marker])
        try:
            message = json.loads(line[marker + len(PROMPT_PREFIX):])
        except json.JSONDecodeError:
            self.emit("output", line[marker:] + "\n")
            return
        if message.get("type") == "input":
            self.secret = bool(message.get("secret", False))
            self.awaiting_input = True
            self.events.put(EngineEvent("input", "Input required", {"secret": self.secret, "prompt": str(message.get("prompt") or "")}))
        elif message.get("type") == "data" and isinstance(message.get("kind"), str) and isinstance(message.get("data"), dict):
            self.events.put(EngineEvent("data", message["kind"], message["data"]))

    def _run(self) -> None:
        self.state = "running"
        command = ["sudo", "-n", str(self.helper), self.key]
        selector = selectors.DefaultSelector()
        stderr_line = ""
        decoders = {
            "stdout": codecs.getincrementaldecoder("utf-8")("replace"),
            "stderr": codecs.getincrementaldecoder("utf-8")("replace"),
        }
        process: subprocess.Popen[bytes] | None = None
        cancel_started: float | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
            with self._process_lock:
                self._process = process
            assert process.stdout is not None and process.stderr is not None
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            self.emit("status", "Terminal workflow started")
            if self.cancelled.is_set():
                process.send_signal(signal.SIGINT)
            while selector.get_map() or process.poll() is None:
                if self.cancelled.is_set():
                    if cancel_started is None:
                        cancel_started = time.monotonic()
                    elapsed = time.monotonic() - cancel_started
                    # Radio modules may need several seconds to stop their
                    # children and restore an adapter before exiting.
                    if elapsed > 30 and process.poll() is None:
                        process.kill()
                    elif elapsed > 20 and process.poll() is None:
                        process.terminate()
                for key, _ in selector.select(timeout=0.05):
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        tail = decoders[key.data].decode(b"", final=True)
                        if key.data == "stderr":
                            stderr_line += tail
                            if stderr_line:
                                self._read_control(stderr_line)
                                stderr_line = ""
                        elif tail:
                            self.emit("output", tail)
                        stream.close()
                        continue
                    text = decoders[key.data].decode(chunk)
                    if key.data == "stdout":
                        if text:
                            self.emit("output", text)
                    else:
                        stderr_line += text
                        while "\n" in stderr_line:
                            line, stderr_line = stderr_line.split("\n", 1)
                            self._read_control(line)
            returncode = process.wait()
            if self.cancelled.is_set():
                self.state = "cancelled"
            elif returncode == 0:
                self.state = "completed"
            else:
                self.state = "error"
                self.emit("error", f"Module exited with code {returncode}")
            self.emit("finished", self.state)
        except Exception as exc:
            self.state = "error"
            self.emit("error", f"Could not start terminal workflow: {exc}")
            self.emit("finished", self.state)
        finally:
            selector.close()
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()

