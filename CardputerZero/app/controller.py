"""Screen navigation and nonblocking interaction with core.engine."""

from __future__ import annotations

import queue
import re
import threading
import textwrap
import time
from dataclasses import dataclass, field

from core.engine import ModuleInfo, Operation, SwissKnifeEngine, module_status
from core.hardware import HardwareSnapshot
from core.terminal_buffer import TerminalBuffer
from core.gui_choices import current_choices
from swiss_knife import MAIN_MENU, ATTACKS_MENU, WARDRIVE_MENU


MAIN = tuple(item["name"] for item in MAIN_MENU.values())
SUBMENUS = {
    "Attacks": tuple(item["name"] for item in ATTACKS_MENU.values()),
    "Wardrive": tuple(item["name"] for item in WARDRIVE_MENU.values()),
}
SPLASH_DELAY = 2.5


@dataclass
class ViewState:
    screen: str = "splash"
    title: str = "SwissKnife"
    rows: list[str] = field(default_factory=list)
    selected: int = 0
    scroll: int = 0
    hint: str = "ENTER continue"
    status: str = ""
    accent: str = "green"
    simulated: bool = False
    show_prompt: bool = False
    awaiting_input: bool = False
    input_value: str = ""
    secret_input: bool = False
    records: list[dict] = field(default_factory=list)
    summary: str = ""
    prompt_text: str = ""


class Controller:
    def __init__(self, engine: SwissKnifeEngine) -> None:
        self.engine = engine
        self.screen = "splash"
        self.splash_started = time.monotonic()
        self.splash_ready = False
        self.menu = "main"
        self.return_menu = "main"
        self.module: ModuleInfo | None = None
        self.hardware: HardwareSnapshot | None = None
        self.operation: Operation | None = None
        self.logs: list[str] = []
        self.console = TerminalBuffer(max_lines=1000)
        self.awaiting_input = False
        self.secret_input = False
        self.input_value = ""
        self.follow_output = True
        self.records: list[dict] = []
        self.record_summary = ""
        self.record_kind = ""
        self.choices: list[tuple[str, str]] = []
        self.choice_index = 0
        self.error = ""
        self.selected = 0
        self.scroll = 0
        self.theme_bright = False
        self.quit_requested = False
        self.dirty = True
        self._hardware_events: queue.Queue[HardwareSnapshot | Exception] = queue.Queue()
        self.refresh_hardware()

    def refresh_hardware(self) -> None:
        def worker() -> None:
            try:
                self._hardware_events.put(self.engine.hardware())
            except Exception as exc:
                self._hardware_events.put(exc)
        threading.Thread(target=worker, daemon=True).start()

    def tick(self) -> bool:
        changed = self.dirty
        self.dirty = False
        if self.screen == "splash" and not self.splash_ready and time.monotonic() - self.splash_started >= SPLASH_DELAY:
            self.splash_ready = True
            changed = True
        try:
            while True:
                result = self._hardware_events.get_nowait()
                if isinstance(result, Exception):
                    self.error = f"Hardware discovery: {result}"
                else:
                    self.hardware = result
                changed = True
        except queue.Empty:
            pass
        if self.operation:
            for event in self.operation.poll():
                if event.kind == "output":
                    self.console.feed(event.message)
                    if self.follow_output:
                        self.scroll = max(0, len(self._wrap(self.console.visible_lines(), 31)) - 5)
                elif event.kind == "input":
                    self.awaiting_input = True
                    self.secret_input = bool(event.data.get("secret", False))
                    self.input_value = ""
                    prompt = self.console.prompt()
                    wants_choice = bool(re.search(r"\b(select|choose|choice|option|number)\b", prompt, re.IGNORECASE))
                    self.choices = current_choices(self.console.visible_lines()) if wants_choice and not self.secret_input else []
                    self.choice_index = 0
                elif event.kind == "data" and event.message == "recon_networks":
                    self.records = list(event.data.get("networks", []))
                    mode = str(event.data.get("mode", "scan"))
                    count = len(self.records)
                    if mode == "sniffer":
                        self.record_summary = f"{count} AP  {event.data.get('packets') or 0} pkt"
                    elif event.data.get("remaining") is not None:
                        self.record_summary = f"{count} AP  {event.data['remaining']}s left"
                    else:
                        self.record_summary = f"{count} networks"
                    self.selected = min(self.selected, max(0, count - 1))
                    self.record_kind = "recon_networks"
                elif event.kind == "data" and event.message in {"arp_devices", "camera_candidates"}:
                    self.records = list(event.data.get("records", []))
                    self.record_kind = event.message
                    self.record_summary = f"{len(self.records)} devices" if event.message == "arp_devices" else f"{len(self.records)} candidates"
                    self.selected = min(self.selected, max(0, len(self.records) - 1))
                elif event.kind == "data" and event.message == "wardrive_cycle":
                    self.records = list(event.data.get("records", []))
                    self.record_kind = "wardrive_cycle"
                    self.record_summary = f"{len(self.records)} AP  {event.data.get('total') or 0} saved"
                    self.selected = min(self.selected, max(0, len(self.records) - 1))
                if event.kind in {"status", "result", "progress", "error"}:
                    self.logs.append(event.message)
                    self.logs = self.logs[-500:]
                    if event.kind == "error":
                        self.console.feed("Error: " + event.message + "\n")
                if event.kind == "error":
                    self.error = event.message
                    self.screen = "results"
                elif event.kind == "finished" and self.screen == "running":
                    self.awaiting_input = False
                    self.screen = "results"
                changed = True
        return changed

    def _menu_rows(self) -> list[str]:
        return list(MAIN if self.menu == "main" else SUBMENUS[self.menu])

    def _open_module(self, label: str) -> None:
        self.module = next((item for item in self.engine.modules() if item.label == label), None)
        if self.module is None:
            self.error = f"Module unavailable: {label}"
            self._goto("error")
        else:
            self.return_menu = self.menu
            self._goto("detail")

    @staticmethod
    def _wrap(rows: list[str], width: int = 31) -> list[str]:
        return [line for row in rows for line in (textwrap.wrap(str(row), width=width, break_long_words=True) or [""])]

    def view(self) -> ViewState:
        common = dict(selected=self.selected, scroll=self.scroll, simulated=self.engine.demo)
        if self.screen == "splash":
            return ViewState(screen="splash", show_prompt=self.splash_ready, simulated=self.engine.demo)
        if self.screen == "menu":
            return ViewState(screen="list", title="MAIN MENU" if self.menu == "main" else self.menu.upper(), rows=self._menu_rows(), hint="F/X move  ENTER select  ESC back", **common)
        if self.screen == "detail":
            assert self.module
            status, reason = module_status(self.module, self.hardware) if self.hardware else ("requires_configuration", "Detecting hardware")
            labels = {"needs_device_test": "Ready to start", "missing_dependency": "Missing tool", "missing_hardware": "Hardware unavailable", "requires_configuration": "Checking hardware"}
            rows = [self.module.description, labels.get(status, status.replace('_', ' '))]
            if status in {"missing_dependency", "missing_hardware"}:
                rows.append(reason)
            rows.append("ENTER opens this module")
            return ViewState(screen="detail", title=self.module.label.upper(), rows=self._wrap(rows), hint="ENTER run  ESC back", status=status, accent="amber" if status != "needs_device_test" else "green", **common)
        if self.screen == "confirm":
            assert self.module
            rows = [f"Run {self.module.label} as root?", "The module asks the same questions as in the terminal."]
            if self.module.needs_wifi:
                rows.append("Changing Wi-Fi mode or network may interrupt SSH and the management connection.")
            rows += ["ENTER start", "ESC back"]
            return ViewState(screen="detail", title="CONFIRM / " + self.module.label.upper(), rows=self._wrap(rows), hint="ENTER start  ESC back", accent="amber", **common)
        if self.screen in {"running", "results"}:
            if self.awaiting_input and self.choices:
                return ViewState(screen="list", title=(self.console.prompt() or "CHOOSE")[:28], rows=[f"{key}  {label}" for key, label in self.choices], selected=self.choice_index, hint="UP/DOWN select  ENTER", simulated=self.engine.demo)
            if self.records and self.record_kind:
                title = {"recon_networks": "RECON / NETWORKS", "arp_devices": "ARP / DEVICES", "camera_candidates": "IP.CAM / CANDIDATES", "wardrive_cycle": "WARDRIVE / NETWORKS"}[self.record_kind]
                return ViewState(screen="networks", title=title, records=self.records, summary=self.record_summary, hint="UP/DOWN browse  ENTER details", status=self.operation.state if self.operation else "", awaiting_input=self.awaiting_input, input_value=self.input_value, secret_input=self.secret_input, prompt_text=self.console.prompt(), **common)
            terminal_rows = self._wrap(self.console.visible_lines(), 31)
            rows = terminal_rows if terminal_rows else self._wrap(self.logs[-500:])
            return ViewState(screen="log", title=("RUN / " if self.screen == "running" else "RESULT / ") + (self.module.label.upper() if self.module else ""), rows=rows, hint="TYPE answer  ENTER submit" if self.awaiting_input else ("ESC cancel  HOME menu" if self.screen == "running" else "ESC back  HOME menu"), status=self.operation.state if self.operation else "", accent="amber" if self.screen == "running" else "green", awaiting_input=self.awaiting_input, input_value=self.input_value, secret_input=self.secret_input, prompt_text=self.console.prompt(), **common)
        if self.screen == "error":
            return ViewState(screen="detail", title="ERROR", rows=self._wrap([self.error]), hint="ESC back  HOME menu", accent="amber", **common)
        if self.screen == "network_detail" and self.records:
            record = self.records[self.selected]
            rows = [f"{key.upper()}: {value}" for key, value in record.items() if value is not None and value != ""]
            return ViewState(screen="detail", title="NETWORK", rows=self._wrap(rows), hint="ESC back", **common)
        return ViewState(screen="detail", title="EXIT", rows=["Returning to APPLaunch"], hint="", **common)

    def _goto(self, screen: str) -> None:
        self.screen = screen
        self.selected = 0
        self.scroll = 0
        self.dirty = True

    def handle(self, key: str, char: str = "") -> None:
        if self.quit_requested:
            return
        if self.screen == "splash":
            if self.splash_ready:
                self._goto("menu")
            return
        if key == "HOME":
            if self.operation and self.operation.state == "running":
                self.operation.cancel()
            self.menu = "main"
            self._goto("menu")
            return
        if key == "ESC":
            if self.screen == "running":
                if self.operation:
                    self.operation.cancel()
                self.dirty = True
                return
            if self.screen == "menu":
                if self.menu == "main":
                    self.quit_requested = True
                else:
                    self.menu = "main"
                    self._goto("menu")
                return
            back = {"detail": "menu", "confirm": "detail", "results": "detail", "error": "detail", "network_detail": "results"}
            if self.screen == "detail":
                self.menu = self.return_menu
            self._goto(back.get(self.screen, "menu"))
            if self.screen == "exit":
                self.quit_requested = True
            return
        if self.screen == "running" and self.awaiting_input:
            if self.choices and key in {"UP", "DOWN", "PAGEUP", "PAGEDOWN"}:
                step = {"UP": -1, "DOWN": 1, "PAGEUP": -4, "PAGEDOWN": 4}[key]
                self.choice_index = max(0, min(len(self.choices) - 1, self.choice_index + step))
                self.dirty = True
                return
            if key == "BACKSPACE":
                self.input_value = self.input_value[:-1]
                self.dirty = True
                return
            if key == "TEXT" and char and char.isprintable() and len(self.input_value) < 256:
                self.input_value += char
                self.dirty = True
                return
            if key == "ENTER":
                try:
                    answer = self.choices[self.choice_index][0] if self.choices else self.input_value
                    self.operation.send(answer)  # type: ignore[attr-defined]
                except Exception as exc:
                    self.error = str(exc)
                    self.console.feed("Error: " + self.error + "\n")
                else:
                    self.awaiting_input = False
                    self.input_value = ""
                    self.choices = []
                self.dirty = True
                return
        if key in {"UP", "DOWN", "PAGEUP", "PAGEDOWN"}:
            step = {"UP": -1, "DOWN": 1, "PAGEUP": -5, "PAGEDOWN": 5}[key]
            if self.screen in {"running", "results"} and self.records:
                self.selected = max(0, min(len(self.records) - 1, self.selected + step))
                self.dirty = True
                return
            rows = self.view().rows
            if self.screen in {"running", "results", "hardware", "detail", "confirm", "error"}:
                self.scroll = max(0, min(max(0, len(rows) - 5), self.scroll + step))
                if self.screen in {"running", "results"}:
                    self.follow_output = self.scroll >= max(0, len(rows) - 5)
            elif rows:
                self.selected = max(0, min(len(rows) - 1, self.selected + step))
            self.dirty = True
            return
        if self.screen == "menu" and key == "ENTER":
            label = self._menu_rows()[self.selected]
            if label == "Exit":
                self.quit_requested = True
            elif label == "Back":
                self.menu = "main"
                self._goto("menu")
            elif self.menu == "main" and label in SUBMENUS:
                self.menu = label
                self._goto("menu")
            else:
                self._open_module(label)
            return
        if self.screen == "detail" and key == "ENTER" and self.module and self.module.enabled:
            self._goto("confirm")
            return
        if self.screen == "confirm" and key == "ENTER":
            self._start_operation()
            return
        if self.screen == "results" and self.records and key == "ENTER":
            self.screen = "network_detail"
            self.dirty = True
            return

    def _start_operation(self) -> None:
        if self.operation and self.operation.state in {"starting", "running"}:
            self.error = "Previous operation is still stopping"
            self._goto("error")
            return
        if not self.module:
            self.error = "No module selected"
            self._goto("error")
            return
        try:
            self.operation = self.engine.start_terminal(self.module.key)
        except Exception as exc:
            self.error = str(exc)
            self._goto("error")
            return
        self.logs = ["[SIMULATED WORKFLOW]" if self.engine.demo else "Started"]
        self.console = TerminalBuffer(max_lines=1000)
        self.records = []
        self.record_summary = ""
        self.record_kind = ""
        self.choices = []
        self.console.feed(self.logs[0] + "\n")
        self.awaiting_input = False
        self.input_value = ""
        self.follow_output = True
        self._goto("running")
