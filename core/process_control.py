"""Run a bounded child process that can be stopped by a GUI operation."""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Sequence


def run_cancellable(
    args: Sequence[str], *, timeout: float, cancel_event: threading.Event
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + timeout
    try:
        while True:
            if cancel_event.is_set():
                process.terminate()
                try:
                    process.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                return subprocess.CompletedProcess(args, process.returncode, "", "cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            try:
                stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
