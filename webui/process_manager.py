#!/usr/bin/env python3

from __future__ import annotations

import os
import fcntl
import selectors
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ModuleSpec:
    module_id: str
    name: str
    script: str
    description: str
    default_args: Tuple[str, ...] = ()


DEFAULT_MODULES: Tuple[ModuleSpec, ...] = (
    ModuleSpec(
        module_id="recon_scan",
        name="Recon Scanner",
        script="webui/actions/recon_scan.py",
        description="Passive AP/client scan without interactive prompts.",
    ),
    ModuleSpec(
        module_id="recon_sniff",
        name="Recon Sniffer",
        script="webui/actions/recon_sniff.py",
        description="Continuous sniffing session with timed stop support.",
    ),
    ModuleSpec(
        module_id="deauth",
        name="Deauth",
        script="modules/deauth.py",
        description="Deauthentication workflow.",
    ),
    ModuleSpec(
        module_id="portal",
        name="Portal",
        script="modules/portal.py",
        description="Captive portal workflow.",
    ),
    ModuleSpec(
        module_id="twins",
        name="Evil Twin",
        script="modules/twins.py",
        description="Evil Twin workflow.",
    ),
    ModuleSpec(
        module_id="bluetooth",
        name="Bluetooth",
        script="modules/bluetooth.py",
        description="Bluetooth and BLE workflows.",
    ),
    ModuleSpec(
        module_id="handshaker",
        name="Handshaker",
        script="modules/handshaker.py",
        description="Under-construction handshaker module.",
    ),
)


class TaskError(RuntimeError):
    pass


@dataclass
class ManagedTask:
    task_id: str
    module: ModuleSpec
    command: List[str]
    process: subprocess.Popen
    started_at: float
    max_log_lines: int = 4000
    status: str = "running"
    returncode: Optional[int] = None
    ended_at: Optional[float] = None
    _next_seq: int = 1
    _logs: Deque[Tuple[int, str]] = field(default_factory=deque)
    _condition: threading.Condition = field(default_factory=threading.Condition)
    _reader_thread: Optional[threading.Thread] = None

    def __post_init__(self) -> None:
        self._logs = deque(maxlen=self.max_log_lines)
        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            name=f"task-reader-{self.task_id}",
            daemon=True,
        )
        self._reader_thread.start()
        self.append_log(f"[webui] started task {self.task_id} ({self.module.name})")

    @property
    def is_running(self) -> bool:
        return self.status == "running"

    def snapshot(self) -> Dict[str, object]:
        return {
            "task_id": self.task_id,
            "module_id": self.module.module_id,
            "module_name": self.module.name,
            "command": self.command,
            "pid": self.process.pid if self.process else None,
            "status": self.status,
            "running": self.is_running,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }

    def append_log(self, message: str) -> None:
        clean = message.rstrip("\r\n")
        with self._condition:
            seq = self._next_seq
            self._next_seq += 1
            self._logs.append((seq, clean))
            self._condition.notify_all()

    def send_input(self, text: str) -> None:
        if not self.is_running:
            raise TaskError("Task is not running.")

        if self.process.stdin is None:
            raise TaskError("Task stdin is unavailable.")

        payload = text if text.endswith("\n") else f"{text}\n"
        try:
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TaskError(f"Could not write to task stdin: {exc}") from exc

    def wait_for_logs(
        self,
        since: int = 0,
        timeout: float = 0.0,
    ) -> Tuple[List[Dict[str, object]], int, int, bool]:
        with self._condition:
            latest_seq = self._next_seq - 1
            if timeout > 0 and since >= latest_seq and self.is_running:
                self._condition.wait(timeout=timeout)

            if self._logs:
                first_seq = self._logs[0][0]
            else:
                first_seq = self._next_seq

            if since < first_seq - 1:
                entries = list(self._logs)
            else:
                entries = [entry for entry in self._logs if entry[0] > since]

            latest_seq = self._next_seq - 1
            payload = [
                {
                    "seq": seq,
                    "line": line,
                }
                for seq, line in entries
            ]

            return payload, latest_seq, first_seq, self.is_running

    def stop(self, graceful_timeout: float = 3.0) -> None:
        if not self.is_running:
            return

        self.append_log("[webui] stopping task...")
        self._signal_process(signal.SIGINT)
        if self._wait_until_exit(graceful_timeout):
            return

        self._signal_process(signal.SIGTERM)
        if self._wait_until_exit(2.0):
            return

        self._signal_process(signal.SIGKILL)
        self._wait_until_exit(1.0)

    def _signal_process(self, sig: signal.Signals) -> None:
        if self.process.poll() is not None:
            return
        try:
            os.killpg(self.process.pid, sig)
        except Exception:
            try:
                self.process.send_signal(sig)
            except Exception:
                pass

    def _wait_until_exit(self, timeout: float) -> bool:
        if self.process.poll() is not None:
            return True
        try:
            self.process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def _reader_loop(self) -> None:
        stream = self.process.stdout
        if stream is None:
            self.append_log("[webui] no stdout stream available")
            self._finish(self.process.wait())
            return

        fd = stream.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_READ)
        buffer = ""
        last_chunk_at = time.monotonic()

        try:
            while True:
                events = selector.select(timeout=0.15)
                if events:
                    try:
                        chunk = os.read(fd, 4096)
                    except BlockingIOError:
                        chunk = b""

                    if not chunk:
                        if self.process.poll() is not None:
                            if buffer:
                                self.append_log(buffer)
                                buffer = ""
                            break
                        continue

                    decoded = chunk.decode(errors="replace")
                    last_chunk_at = time.monotonic()
                    for char in decoded:
                        if char in ("\r", "\n"):
                            self.append_log(buffer)
                            buffer = ""
                        else:
                            buffer += char
                else:
                    if buffer and (time.monotonic() - last_chunk_at) > 0.2:
                        # Flush pending prompt fragments for input()-style prompts.
                        self.append_log(buffer)
                        buffer = ""
                    if self.process.poll() is not None:
                        if buffer:
                            self.append_log(buffer)
                            buffer = ""
                        break
        finally:
            selector.close()
            try:
                stream.close()
            except Exception:
                pass

        code = self.process.poll()
        if code is None:
            code = self.process.wait()
        self._finish(code)

    def _finish(self, returncode: int) -> None:
        with self._condition:
            if self.status != "running":
                return
            self.status = "stopped"
            self.returncode = returncode
            self.ended_at = time.time()
            self._condition.notify_all()
        self.append_log(f"[webui] task exited with code {returncode}")


class ProcessManager:
    def __init__(
        self,
        project_root: Path = PROJECT_ROOT,
        modules: Tuple[ModuleSpec, ...] = DEFAULT_MODULES,
        max_log_lines: int = 4000,
    ) -> None:
        self.project_root = project_root
        self.max_log_lines = max_log_lines
        self._modules: Dict[str, ModuleSpec] = {item.module_id: item for item in modules}
        self._tasks: Dict[str, ManagedTask] = {}
        self._active_task_id: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def active_task_id(self) -> Optional[str]:
        with self._lock:
            self._refresh_active_locked()
            return self._active_task_id

    def list_modules(self) -> List[Dict[str, object]]:
        payload: List[Dict[str, object]] = []
        for item in self._modules.values():
            script_path = self.project_root / item.script
            payload.append(
                {
                    "module_id": item.module_id,
                    "name": item.name,
                    "description": item.description,
                    "script": item.script,
                    "exists": script_path.is_file(),
                    "default_args": list(item.default_args),
                }
            )
        return payload

    def list_tasks(self) -> List[Dict[str, object]]:
        with self._lock:
            self._refresh_active_locked()
            ordered = sorted(self._tasks.values(), key=lambda task: task.started_at, reverse=True)
            return [task.snapshot() for task in ordered]

    def start_task(self, module_id: str, args: Optional[List[str]] = None) -> Dict[str, object]:
        module = self._modules.get(module_id)
        if not module:
            raise KeyError(f"Unknown module '{module_id}'.")

        script_path = self.project_root / module.script
        if not script_path.is_file():
            raise FileNotFoundError(f"Script not found: {script_path}")

        with self._lock:
            self._refresh_active_locked()
            if self._active_task_id:
                active = self._tasks.get(self._active_task_id)
                if active and active.is_running:
                    raise TaskError(
                        f"Task {active.task_id} ({active.module.name}) is already running."
                    )

            task_id = uuid.uuid4().hex[:10]
            final_args = list(module.default_args)
            if args:
                final_args.extend(args)
            cmd = [sys.executable or "python3", str(script_path), *final_args]

            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env.setdefault("TERM", "xterm-256color")

            try:
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(self.project_root),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                    env=env,
                )
            except OSError as exc:
                raise TaskError(f"Failed to start module '{module.name}': {exc}") from exc

            task = ManagedTask(
                task_id=task_id,
                module=module,
                command=cmd,
                process=proc,
                started_at=time.time(),
                max_log_lines=self.max_log_lines,
            )
            self._tasks[task_id] = task
            self._active_task_id = task_id
            return task.snapshot()

    def stop_task(self, task_id: str) -> Dict[str, object]:
        task = self._get_task(task_id)
        task.stop()
        with self._lock:
            self._refresh_active_locked()
        return task.snapshot()

    def send_input(self, task_id: str, text: str) -> Dict[str, object]:
        task = self._get_task(task_id)
        task.send_input(text)
        return task.snapshot()

    def get_task_snapshot(self, task_id: str) -> Dict[str, object]:
        task = self._get_task(task_id)
        return task.snapshot()

    def wait_for_logs(
        self,
        task_id: str,
        since: int = 0,
        timeout: float = 0.0,
    ) -> Tuple[List[Dict[str, object]], int, int, bool]:
        task = self._get_task(task_id)
        return task.wait_for_logs(since=since, timeout=timeout)

    def shutdown(self) -> None:
        with self._lock:
            tasks = list(self._tasks.values())
        for task in tasks:
            if task.is_running:
                task.stop()

    def _refresh_active_locked(self) -> None:
        if not self._active_task_id:
            return
        active = self._tasks.get(self._active_task_id)
        if not active or not active.is_running:
            self._active_task_id = None

    def _get_task(self, task_id: str) -> ManagedTask:
        with self._lock:
            task = self._tasks.get(task_id)
        if not task:
            raise KeyError(f"Task '{task_id}' not found.")
        return task
