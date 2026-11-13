"""Screen navigation and nonblocking interaction with core.engine."""

from __future__ import annotations

import queue
import threading
import textwrap
import time
from dataclasses import dataclass, field

from core.engine import ModuleInfo, Operation, SwissKnifeEngine, compatibility_issues, module_status
from core.hardware import HardwareSnapshot
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
        self.error = ""
        self.selected = 0
        self.scroll = 0
        self.interface_index = 0
        self.duration = 5
        self.cycles = 3
        self.max_hosts = 64
        self.filter_text = ""
        self.confirm_management = False
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
                    self.interface_index = min(self.interface_index, max(0, len(result.wifi) - 1))
                    if self.screen == "config":
                        self.selected = min(self.selected, len(self._config_rows()) - 1)
                changed = True
        except queue.Empty:
            pass
        if self.operation:
            for event in self.operation.poll():
                if event.kind in {"status", "result", "progress", "error"}:
                    self.logs.append(event.message)
                    self.logs = self.logs[-500:]
                if event.kind == "error":
                    self.error = event.message
                    self.screen = "error"
                elif event.kind == "finished" and self.screen == "running":
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

    def _config_rows(self) -> list[str]:
        interface = "none"
        if self.hardware and self.hardware.wifi:
            interface = self.hardware.wifi[self.interface_index].name
        rows = []
        if self.module and self.module.needs_wifi:
            rows.append(f"Interface  {interface}")
        if self.module and self.module.key in {"Recon", "Start Wardrive"}:
            rows.append(f"Duration   {self.duration}s")
            rows.append(f"SSID filter  {self.filter_text or '(all)'}")
        if self.module and self.module.key == "Start Wardrive":
            rows.append(f"Cycles     {self.cycles}")
        if self.module and self.module.key in {"ARP scan", "IP.CAM finder"}:
            rows.append(f"Host limit {self.max_hosts}")
        if self.hardware and self.hardware.wifi and self.module and self.module.needs_wifi:
            selected_interface = self.hardware.wifi[self.interface_index].name
            if selected_interface == self.hardware.default_route:
                rows.append(f"Mgmt Wi-Fi  {'CONFIRMED' if self.confirm_management else 'confirm'}")
        rows.append("START")
        return rows

    @staticmethod
    def _wrap(rows: list[str], width: int = 42) -> list[str]:
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
            issues = compatibility_issues(self.module, self.hardware) if self.hardware else ("Hardware discovery pending",)
            rows = [self.module.description, f"Status: {status.replace('_', ' ')}", reason, f"Tools: {', '.join(self.module.tools)}"]
            rows += [f"Check: {issue}" for issue in issues] if issues else ["Prerequisites detected; device test pending"]
            return ViewState(screen="detail", title=self.module.label.upper(), rows=self._wrap(rows), hint="ENTER configure  ESC back" if self.module.enabled else "INFO ONLY  ESC back", status=status, accent="amber" if status != "needs_device_test" else "green", **common)
        if self.screen == "config":
            return ViewState(screen="list", title=f"SETUP / {self.module.label.upper() if self.module else ''}", rows=self._config_rows(), hint="LEFT/RIGHT change  ENTER", **common)
        if self.screen in {"running", "results"}:
            return ViewState(screen="log", title=("RUN / " if self.screen == "running" else "RESULT / ") + (self.module.label.upper() if self.module else ""), rows=self._wrap(self.logs[-500:]), hint="ESC cancel  HOME menu" if self.screen == "running" else "ESC back  HOME menu", status=self.operation.state if self.operation else "", accent="amber" if self.screen == "running" else "green", **common)
        if self.screen == "error":
            return ViewState(screen="detail", title="ERROR", rows=self._wrap([self.error]), hint="ESC back  HOME menu", accent="amber", **common)
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
            back = {"detail": "menu", "config": "detail", "results": "detail", "error": "detail"}
            if self.screen == "detail":
                self.menu = self.return_menu
            self._goto(back.get(self.screen, "menu"))
            if self.screen == "exit":
                self.quit_requested = True
            return
        if self.screen == "config" and self.selected < len(self._config_rows()) and self._config_rows()[self.selected].startswith("SSID filter"):
            if key == "BACKSPACE":
                self.filter_text = self.filter_text[:-1]
                self.dirty = True
                return
            if key == "TEXT" and char and len(self.filter_text) < 24:
                self.filter_text += char
                self.dirty = True
                return
        if key in {"UP", "DOWN", "PAGEUP", "PAGEDOWN"}:
            step = {"UP": -1, "DOWN": 1, "PAGEUP": -5, "PAGEDOWN": 5}[key]
            rows = self.view().rows
            if self.screen in {"running", "results", "hardware", "detail", "error"}:
                self.scroll = max(0, min(max(0, len(rows) - 5), self.scroll + step))
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
            self._goto("config")
            return
        if self.screen == "config":
            row = self._config_rows()[self.selected]
            delta = -1 if key == "LEFT" else 1
            if key in {"LEFT", "RIGHT", "ENTER"}:
                if row.startswith("Interface") and self.hardware and self.hardware.wifi:
                    self.interface_index = (self.interface_index + delta) % len(self.hardware.wifi)
                    self.confirm_management = False
                    self.selected = min(self.selected, len(self._config_rows()) - 1)
                elif row.startswith("Duration"):
                    self.duration = max(1, min(60, self.duration + delta))
                elif row.startswith("Cycles"):
                    self.cycles = max(1, min(100, self.cycles + delta))
                elif row.startswith("Host limit"):
                    self.max_hosts = max(32, min(128, self.max_hosts + delta * 8))
                elif row.startswith("Mgmt Wi-Fi"):
                    self.confirm_management = not self.confirm_management
                elif row == "START" and key == "ENTER":
                    self._start_operation()
                self.dirty = True
            return

    def _start_operation(self) -> None:
        if self.operation and self.operation.state in {"starting", "running"}:
            self.error = "Previous operation is still stopping"
            self._goto("error")
            return
        if not self.module or not self.hardware:
            self.error = "Hardware discovery is not complete"
            self._goto("error")
            return
        interface = self.hardware.wifi[self.interface_index].name if self.hardware.wifi else ""
        config = {"interface": interface, "duration": self.duration, "cycles": self.cycles, "max_hosts": self.max_hosts, "filter": self.filter_text, "allow_management_interface": self.confirm_management}
        try:
            self.operation = self.engine.start(self.module.key, config, hardware=self.hardware)
        except Exception as exc:
            self.error = str(exc)
            self._goto("error")
            return
        self.logs = ["[SIMULATED RESULTS]" if self.engine.demo else "Started"]
        self._goto("running")
