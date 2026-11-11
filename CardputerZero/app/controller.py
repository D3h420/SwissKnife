"""Screen navigation and nonblocking interaction with core.engine."""

from __future__ import annotations

import queue
import threading
import textwrap
import time
from dataclasses import dataclass, field, replace

from core.engine import ModuleInfo, Operation, SwissKnifeEngine, compatibility_issues, module_status
from core.hardware import HardwareSnapshot
from modules.sdr import MODULATIONS, PRESETS, SDRSession, SDRSnapshot


MAIN = ("Modules", "SDR", "Hardware", "Settings", "Exit")
CATEGORIES = ("Recon", "Diagnostics", "Wardrive", "Attacks")


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
    sdr: SDRSnapshot | None = None
    sdr_error: str = ""
    sdr_step_hz: int = 100_000


class Controller:
    def __init__(self, engine: SwissKnifeEngine) -> None:
        self.engine = engine
        self.categories = tuple(dict.fromkeys((*CATEGORIES, *(module.category for module in engine.modules()))))
        self.screen = "splash"
        self.category = "Recon"
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
        self.sdr: SDRSession | None = None
        self.sdr_snapshot: SDRSnapshot | None = None
        self.sdr_error = ""
        self.sdr_busy = False
        self.sdr_pending_stop = False
        self.sdr_worker: threading.Thread | None = None
        self.sdr_step_hz = 100_000
        self.sdr_tune_text = ""
        self.sdr_last_poll = 0.0
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
        if self.screen == "sdr" and self.sdr is not None and time.monotonic() - self.sdr_last_poll >= 0.25:
            self.sdr_last_poll = time.monotonic()
            self.sdr_snapshot = self.sdr.snapshot()
            changed = True
        return changed

    def _module_list(self) -> list[ModuleInfo]:
        return [item for item in self.engine.modules() if item.category == self.category]

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
            return ViewState(screen="splash", rows=["LAB5 / D3h420", "One engine. Three interfaces."], hint="ENTER open", simulated=self.engine.demo)
        if self.screen == "main":
            return ViewState(screen="list", title="SWISSKNIFE / HOME", rows=list(MAIN), hint="F/X move  ENTER select", **common)
        if self.screen == "sdr":
            return ViewState(screen="sdr", title="SDR / RTL", rows=[], hint="F/X band Z/C tune  R rec A audio D ADSB", sdr=self.sdr_snapshot, sdr_error=self.sdr_error, sdr_step_hz=self.sdr_step_hz, **common)
        if self.screen == "sdr_tune":
            return ViewState(screen="detail", title="SDR / FREQUENCY", rows=["Enter frequency in MHz:", self.sdr_tune_text + "_", self.sdr_error], hint="ENTER apply  ESC back", **common)
        if self.screen == "categories":
            return ViewState(screen="list", title="CATEGORIES", rows=list(self.categories), hint="ESC back  ENTER open", **common)
        if self.screen == "modules":
            rows = []
            for item in self._module_list():
                code = "?"
                if self.hardware:
                    status, _ = module_status(item, self.hardware)
                    code = {"needs_device_test": "~", "missing_dependency": "!", "missing_hardware": "!", "unsupported": "-"}[status]
                rows.append(f"{code}  {item.label}")
            return ViewState(screen="list", title=self.category.upper(), rows=rows, hint="~ test  ! missing  - info", **common)
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
        if self.screen == "hardware":
            rows = ["Detecting hardware..."]
            if self.hardware:
                rows = [f"Route: {self.hardware.default_route or 'none'}", f"Privilege: {'root' if self.hardware.is_root else 'user'}"]
                rows += [f"Wi-Fi {item.name} {'USB' if item.usb else 'built-in'} {item.mode} monitor={item.monitor_supported}" for item in self.hardware.wifi]
                rows += [f"USB {item}" for item in self.hardware.usb]
                rows += [f"GPS {item}" for item in self.hardware.gps_ports]
                if not self.hardware.wifi:
                    rows.append("No Wi-Fi adapters detected")
            return ViewState(screen="log", title="HARDWARE", rows=self._wrap(rows), hint="R refresh  ESC back", **common)
        if self.screen == "settings":
            return ViewState(screen="list", title="SETTINGS", rows=[f"Bright accents  {'ON' if self.theme_bright else 'OFF'}", "Refresh hardware", "About LAB5 / D3h420"], hint="ENTER toggle  ESC back", **common)
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
            self._goto("main")
            return
        if key == "HOME":
            if self.operation and self.operation.state == "running":
                self.operation.cancel()
            if self.screen == "sdr":
                self._sdr_action("stop")
            self._goto("main")
            return
        if key == "ESC":
            if self.screen == "sdr_tune":
                self._goto("sdr")
                return
            if self.screen == "sdr":
                self._sdr_action("stop")
                self._goto("main")
                return
            if self.screen == "running":
                if self.operation:
                    self.operation.cancel()
                self.dirty = True
                return
            back = {"main": "exit", "categories": "main", "modules": "categories", "detail": "modules", "config": "detail", "results": "detail", "hardware": "main", "settings": "main", "error": "detail"}
            self._goto(back.get(self.screen, "main"))
            if self.screen == "exit":
                self.quit_requested = True
            return
        if self.screen == "sdr":
            self._sdr_key(key, char)
            return
        if self.screen == "sdr_tune":
            if key == "BACKSPACE":
                self.sdr_tune_text = self.sdr_tune_text[:-1]
            elif key == "TEXT" and char in "0123456789." and len(self.sdr_tune_text) < 12:
                self.sdr_tune_text += char
            elif key == "ENTER":
                try:
                    center = round(float(self.sdr_tune_text) * 1_000_000)
                    if self.sdr is None:
                        raise ValueError("SDR session unavailable")
                    replace(self.sdr.config, center_hz=center).validate()
                except ValueError as exc:
                    self.sdr_error = str(exc)
                else:
                    self._goto("sdr")
                    self._sdr_action("spectrum", center_hz=center)
            self.dirty = True
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
        if self.screen == "main" and key == "ENTER":
            target = MAIN[self.selected]
            self._goto({"Modules": "categories", "SDR": "sdr", "Hardware": "hardware", "Settings": "settings", "Exit": "exit"}[target])
            if target == "SDR":
                self._open_sdr()
            if target == "Exit":
                self.quit_requested = True
            return
        if self.screen == "categories" and key == "ENTER":
            self.category = self.categories[self.selected]
            self._goto("modules")
            return
        if self.screen == "modules" and key == "ENTER":
            choices = self._module_list()
            if choices:
                self.module = choices[self.selected]
                self._goto("detail")
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
        if self.screen == "hardware" and key == "TEXT" and char.lower() == "r":
            self.refresh_hardware()
            self.dirty = True
        if self.screen == "settings" and key == "ENTER":
            if self.selected == 0:
                self.theme_bright = not self.theme_bright
            elif self.selected == 1:
                self.refresh_hardware()
            self.dirty = True

    def _open_sdr(self) -> None:
        if self.sdr is None:
            self.sdr = SDRSession(demo=self.engine.demo)
        self._sdr_action("spectrum")

    def _sdr_action(self, action: str, **changes) -> None:
        if self.sdr_busy:
            if action == "stop":
                self.sdr_pending_stop = True
            return
        if self.sdr is None:
            return
        self.sdr_busy = True
        self.sdr_error = ""

        def worker() -> None:
            try:
                session = self.sdr
                if not session.devices and action != "stop":
                    if not session.refresh_devices():
                        raise RuntimeError("No RTL-SDR dongle detected")
                previous = session.mode
                if action == "retune" and previous in {"record", "adsb"}:
                    raise RuntimeError("Stop recording or ADS-B before changing SDR settings")
                if changes:
                    session.update_config(restart=action == "retune", **changes)
                if action == "spectrum":
                    session.start_spectrum()
                elif action == "audio":
                    session.start_audio()
                elif action == "record":
                    session.start_recording(seconds=30)
                elif action == "adsb":
                    session.start_adsb()
                elif action == "stop":
                    session.stop()
                elif action == "retune" and previous == "audio":
                    session.start_audio()
            except Exception as exc:
                self.sdr_error = str(exc)
            finally:
                try:
                    if self.sdr_pending_stop:
                        self.sdr_pending_stop = False
                        self.sdr.stop()
                finally:
                    self.sdr_busy = False
                    self.dirty = True

        self.sdr_worker = threading.Thread(target=worker, daemon=True)
        self.sdr_worker.start()

    def _sdr_key(self, key: str, char: str) -> None:
        if self.sdr is None or self.sdr_busy:
            return
        session = self.sdr
        if key in {"LEFT", "RIGHT"}:
            direction = -1 if key == "LEFT" else 1
            self._sdr_action("retune", center_hz=session.config.center_hz + direction * self.sdr_step_hz)
        elif key in {"UP", "DOWN"}:
            current = min(range(len(PRESETS)), key=lambda index: abs(PRESETS[index][1] - session.config.center_hz))
            index = (current + (-1 if key == "UP" else 1)) % len(PRESETS)
            _, center, span = PRESETS[index]
            self._sdr_action("spectrum", center_hz=center, span_hz=span)
        elif key in {"PAGEUP", "PAGEDOWN"}:
            steps = (10_000, 100_000, 1_000_000)
            index = steps.index(self.sdr_step_hz)
            self.sdr_step_hz = steps[(index + (1 if key == "PAGEUP" else -1)) % len(steps)]
            self.dirty = True
        elif key == "ENTER":
            self._sdr_action("spectrum" if session.mode in {"idle", "error"} else "stop")
        elif key == "TEXT":
            command = char.lower()
            if command == "r":
                self._sdr_action("stop" if session.mode == "record" else "record")
            elif command == "a":
                self._sdr_action("stop" if session.mode == "audio" else "audio")
            elif command == "d":
                self._sdr_action("stop" if session.mode == "adsb" else "adsb")
            elif command == "s":
                self._sdr_action("spectrum")
            elif command == "m":
                index = (MODULATIONS.index(session.config.modulation) + 1) % len(MODULATIONS)
                self._sdr_action("retune", modulation=MODULATIONS[index])
            elif command == "n" and session.devices:
                self._sdr_action("spectrum", device=(session.config.device + 1) % len(session.devices))
            elif command == "g":
                gains = (None, 0.0, 10.0, 20.0, 30.0, 40.0)
                current = gains.index(session.config.gain_db) if session.config.gain_db in gains else -1
                self._sdr_action("retune", gain_db=gains[(current + 1) % len(gains)])
            elif command == "p":
                values = (0, 1, 2, 5, 10, -1, -2, -5, -10)
                current = values.index(session.config.ppm) if session.config.ppm in values else -1
                self._sdr_action("retune", ppm=values[(current + 1) % len(values)])
            elif command == "b":
                spans = (200_000, 2_000_000, 20_000_000)
                current = spans.index(session.config.span_hz) if session.config.span_hz in spans else -1
                self._sdr_action("retune", span_hz=spans[(current + 1) % len(spans)])
            elif command == "i":
                rates = (1_024_000, 2_048_000, 2_400_000)
                current = rates.index(session.config.sample_rate) if session.config.sample_rate in rates else -1
                self._sdr_action("retune", sample_rate=rates[(current + 1) % len(rates)])
            elif command == "t":
                self.sdr_tune_text = f"{session.config.center_hz / 1e6:.3f}"
                self.sdr_error = ""
                self._goto("sdr_tune")
            elif command in {"+", "="}:
                self.sdr_step_hz = min(1_000_000, self.sdr_step_hz * 10)
            elif command == "-":
                self.sdr_step_hz = max(10_000, self.sdr_step_hz // 10)
            self.dirty = True

    def close(self) -> None:
        if self.sdr is not None:
            if self.sdr_busy:
                self.sdr_pending_stop = True
                if self.sdr_worker:
                    self.sdr_worker.join(timeout=5)
            self.sdr.close()

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
