"""Screen navigation and nonblocking interaction with core.engine."""

from __future__ import annotations

import queue
import re
import threading
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.engine import ModuleInfo, Operation, SwissKnifeEngine, module_status
from core.hardware import HardwareSnapshot
from core.terminal_buffer import TerminalBuffer
from core.gui_choices import current_choices
from swiss_knife import MAIN_MENU, ATTACKS_MENU, WARDRIVE_MENU


MAIN = tuple(item["name"] for item in MAIN_MENU.values())
SUBMENUS = {
    "Attacks": tuple(item["name"] for item in ATTACKS_MENU.values() if item["name"] != "Back"),
    "Wardrive": tuple(item["name"] for item in WARDRIVE_MENU.values() if item["name"] != "Back"),
}
SPLASH_DELAY = 2.5
SCAN_DEFAULTS = {"Recon": 12, "Start Wardrive": 8, "ARP scan": 15, "IP.CAM finder": 15}
MODULE_COPY = {
    "Recon": "Discover nearby Wi-Fi networks and inspect radio activity.",
    "Deauth": "Manage the existing Deauth workflow.",
    "Portal": "Configure a local captive portal.",
    "Evil Twin": "Configure the Evil Twin workflow.",
    "Handshaker": "Inspect and capture Wi-Fi handshakes.",
    "WiFi Poet": "Configure wireless beacon messages.",
    "Dragon Drain": "Inspect the Dragon Drain workflow.",
    "ARP scan": "Find devices on the connected network.",
    "IP.CAM finder": "Find possible IP cameras on the network.",
    "Start Wardrive": "Record nearby networks with GPS position.",
    "GPS setup": "Check your GPS receiver and position fix.",
}
REPOSITORY_URL = "https://github.com/D3h420/SwissKnife"


def app_version() -> str:
    metadata = Path(__file__).resolve().parents[1] / "packaging" / "meta.env"
    try:
        for line in metadata.read_text().splitlines():
            if line.startswith("PKG_VERSION="):
                return line.partition("=")[2].strip()
    except OSError:
        pass
    return "unknown"


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
    description: str = ""
    status_label: str = ""
    secondary_label: str = ""
    packets: int = 0
    probes: int = 0
    probe_records: list[dict] = field(default_factory=list)
    version: str = ""


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
        self.back_choice = ""
        self.choice_index = 0
        self.scan_durations = dict(SCAN_DEFAULTS)
        self.duration_text = "12"
        self.duration_pristine = True
        self.recon_mode = ""
        self.recon_choice_sent = False
        self.workflow_interface_selected = False
        self.sniffer_active = False
        self.sniffer_post_choice_ready = False
        self.sniffer_exit_requested = False
        self.probe_records: list[dict] = []
        self.packet_count = 0
        self.probe_total = 0
        self.current_prompt = ""
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
                    prompt = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(event.data.get("prompt") or self.console.prompt()))
                    self.current_prompt = prompt
                    automatic = self._automatic_answer(prompt)
                    if automatic is not None:
                        try:
                            self.operation.send(automatic)  # type: ignore[attr-defined]
                        except Exception as exc:
                            self.console.feed(f"Error: {exc}\n")
                        else:
                            self.awaiting_input = False
                            self.choices = []
                            self.back_choice = ""
                            continue
                    if self.module and self.module.key == "Recon" and self.recon_mode == "2":
                        lower_prompt = prompt.casefold()
                        if "press enter to stop sniffer" in lower_prompt:
                            self.sniffer_active = True
                            if self.screen != "sniffer_probes":
                                self.screen = "sniffer_live"
                        elif "your choice" in lower_prompt and "0/2" in lower_prompt:
                            self.sniffer_active = False
                            self.sniffer_post_choice_ready = True
                            self.screen = "sniffer_stopped"
                    wants_choice = bool(re.search(r"\b(select|choose|choice|option|number)\b", prompt, re.IGNORECASE))
                    available = current_choices(self.console.visible_lines()) if wants_choice and not self.secret_input and self.screen not in {"sniffer_stopped", "sniffer_live", "sniffer_probes", "sniffer_aps"} else []
                    self.back_choice = next((key for key, label in available if label.casefold().startswith("back")), "")
                    self.choices = [(key, label) for key, label in available if not label.casefold().startswith("back")]
                    self.choice_index = 0
                elif event.kind == "data" and event.message == "recon_networks":
                    self.records = list(event.data.get("networks", []))
                    mode = str(event.data.get("mode", "scan"))
                    count = len(self.records)
                    if mode == "sniffer":
                        self.record_summary = f"{count} AP  {event.data.get('packets') or 0} pkt"
                        self.packet_count = int(event.data.get("packets") or 0)
                        self.probe_total = int(event.data.get("probes") or 0)
                        self.probe_records = list(event.data.get("probe_records") or [])
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
                elif event.kind == "finished" and self.screen in {"running", "sniffer_live", "sniffer_stopped", "sniffer_probes", "sniffer_aps"}:
                    self.awaiting_input = False
                    if self.sniffer_exit_requested:
                        self.menu = "main"
                        self._goto("menu")
                    else:
                        self.screen = "results"
                changed = True
        return changed

    def _automatic_answer(self, prompt: str) -> str | None:
        if not self.module:
            return None
        lowered = prompt.casefold()
        key = self.module.key
        if key == "Recon" and "your choice" in lowered and "0-2" in lowered:
            if not self.recon_choice_sent and self.recon_mode in {"1", "2"}:
                self.recon_choice_sent = True
                return self.recon_mode
            if self.recon_mode == "1" and self.recon_choice_sent:
                return "0"
        if key == "Recon" and self.recon_mode == "2" and "your choice" in lowered and "0/2" in lowered and self.sniffer_exit_requested:
            return "0"
        if key == "Recon" and self.recon_mode == "1" and "press enter to return" in lowered:
            return ""
        if key in SCAN_DEFAULTS and ("scan duration" in lowered or "scan window" in lowered):
            duration = self.scan_durations[key]
            return "" if duration == SCAN_DEFAULTS[key] else str(duration)
        if not self.workflow_interface_selected:
            return None
        if key == "Recon":
            if "press enter" in lowered and "switch" in lowered and "monitor mode" in lowered:
                return ""
            if self.recon_mode == "1" and "press enter" in lowered and "start scaner" in lowered:
                return ""
            if self.recon_mode == "2" and "press enter" in lowered and "start sniffer" in lowered:
                return ""
        if key == "Start Wardrive":
            if "press enter" in lowered and "switch" in lowered and "managed mode" in lowered:
                return ""
            if "press enter" in lowered and "run gps setup" in lowered:
                return ""
        return None

    def _menu_rows(self) -> list[str]:
        return list(MAIN if self.menu == "main" else SUBMENUS[self.menu])

    def _open_module(self, label: str) -> None:
        self.module = next((item for item in self.engine.modules() if item.label == label), None)
        if self.module is None:
            self.error = f"Module unavailable: {label}"
            self._goto("error")
        else:
            self.return_menu = self.menu
            self._goto("recon_modes" if self.module.key == "Recon" else "detail")

    @staticmethod
    def _wrap(rows: list[str], width: int = 31) -> list[str]:
        return [line for row in rows for line in (textwrap.wrap(str(row), width=width, break_long_words=True) or [""])]

    def view(self) -> ViewState:
        common = dict(selected=self.selected, scroll=self.scroll, simulated=self.engine.demo)
        if self.screen == "splash":
            return ViewState(screen="splash", show_prompt=self.splash_ready, simulated=self.engine.demo)
        if self.screen == "menu":
            return ViewState(screen="list", title="MAIN MENU" if self.menu == "main" else self.menu.upper(), rows=self._menu_rows(), hint="F/X move  ENTER select  A about" if self.menu == "main" else "F/X move  ENTER select  ESC back", **common)
        if self.screen == "about":
            return ViewState(screen="about", title="ABOUT", version=app_version(), hint="ENTER repository QR  ESC back", **common)
        if self.screen == "about_qr":
            return ViewState(screen="about_qr", title="GITHUB", hint="ESC back", **common)
        if self.screen == "recon_modes":
            return ViewState(screen="recon_modes", title="RECON", description=MODULE_COPY["Recon"], rows=["Scaner", "Sniffer"], hint="F/X choose  ENTER open  ESC back", **common)
        if self.screen == "recon_scan_setup":
            return ViewState(screen="recon_scan_setup", title="SCANER", status_label=f"{self.scan_durations['Recon']} s", hint="Z/C ±1  F/X ±5  T type  ENTER start", **common)
        if self.screen in {"sniffer_live", "sniffer_stopped", "sniffer_probes", "sniffer_aps"}:
            phase = "LIVE" if self.sniffer_active else ("READY" if self.sniffer_post_choice_ready else "WORKING")
            return ViewState(screen=self.screen, title="SNIFFER", selected=self.selected, records=self.records, probe_records=self.probe_records, packets=self.packet_count, probes=self.probe_total, status=self.operation.state if self.operation else "", status_label=phase, hint="ENTER select  ESC back", simulated=self.engine.demo)
        if self.screen == "detail":
            assert self.module
            status, reason = module_status(self.module, self.hardware) if self.hardware else ("requires_configuration", "Detecting hardware")
            labels = {"needs_device_test": "Ready", "missing_dependency": "Needs a tool", "missing_hardware": "Hardware unavailable", "requires_configuration": "Checking hardware"}
            rows = [MODULE_COPY.get(self.module.key, self.module.description), labels.get(status, status.replace('_', ' '))]
            if status in {"missing_dependency", "missing_hardware"}:
                rows.append(reason)
            return ViewState(screen="module_detail", title=self.module.label, rows=self._wrap(rows), description=rows[0], status_label=rows[1], hint="ENTER start  ESC back", status=status, secondary_label=f"Time {self.scan_durations[self.module.key]}s" if self.module.key in SCAN_DEFAULTS else "", **common)
        if self.screen == "duration_input":
            return ViewState(screen="duration_input", title="Scan duration", input_value=self.duration_text, rows=["Seconds, 1 to 300"], hint="ENTER save  ESC back", **common)
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
        if self.screen == "menu" and self.menu == "main" and key == "TEXT" and char.lower() == "a":
            self._goto("about")
            return
        if key == "HOME":
            if self.module and self.module.key == "Recon" and self.recon_mode == "2" and self.screen in {"sniffer_live", "sniffer_stopped", "sniffer_probes", "sniffer_aps"}:
                self.sniffer_exit_requested = True
                if self.awaiting_input and self.operation:
                    try:
                        self.operation.send("" if self.sniffer_active else "0")
                        self.awaiting_input = False
                    except RuntimeError:
                        self.operation.cancel()
                elif self.operation:
                    self.operation.cancel()
            elif self.operation and self.operation.state == "running":
                self.operation.cancel()
            self.menu = "main"
            self._goto("menu")
            return
        if key == "ESC":
            if self.screen == "sniffer_probes":
                self._goto("sniffer_live" if self.sniffer_active else "sniffer_stopped")
                return
            if self.screen == "sniffer_aps":
                self._goto("sniffer_live" if self.sniffer_active else "sniffer_stopped")
                return
            if self.screen == "sniffer_live":
                self._stop_sniffer()
                return
            if self.screen == "sniffer_stopped":
                self._leave_sniffer()
                return
            if self.screen == "running":
                if self.operation and self.awaiting_input and self.back_choice:
                    try:
                        self.operation.send(self.back_choice)
                        self.awaiting_input = False
                        self.choices = []
                        self.back_choice = ""
                    except RuntimeError as exc:
                        self.error = str(exc)
                        self._goto("error")
                elif self.operation:
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
            back = {"about": "menu", "about_qr": "about", "recon_modes": "menu", "recon_scan_setup": "recon_modes", "detail": "menu", "duration_input": "recon_scan_setup" if self.module and self.module.key == "Recon" else "detail", "results": "recon_modes" if self.module and self.module.key == "Recon" else "detail", "error": "detail", "network_detail": "results"}
            if self.screen == "detail":
                self.menu = self.return_menu
            self._goto(back.get(self.screen, "menu"))
            if self.screen == "exit":
                self.quit_requested = True
            return
        if self.screen == "duration_input":
            if key == "BACKSPACE":
                self.duration_text = self.duration_text[:-1]
                self.duration_pristine = False
            elif key == "TEXT" and char.isdigit() and len(self.duration_text) < 3:
                self.duration_text = char if self.duration_pristine else self.duration_text + char
                self.duration_pristine = False
            elif key == "ENTER":
                value = int(self.duration_text or "0")
                if 1 <= value <= 300:
                    if self.module and self.module.key in SCAN_DEFAULTS:
                        self.scan_durations[self.module.key] = value
                    self.selected = 0
                    self._goto("recon_scan_setup" if self.module and self.module.key == "Recon" else "detail")
                else:
                    self.error = "Choose 1 to 300 seconds"
                    self._goto("error")
            self.dirty = True
            return
        if self.screen == "about" and key == "ENTER":
            self._goto("about_qr")
            return
        if self.screen == "recon_modes":
            if key in {"UP", "DOWN", "LEFT", "RIGHT"}:
                self.selected = 1 - self.selected
                self.dirty = True
            elif key == "ENTER":
                self.recon_mode = "1" if self.selected == 0 else "2"
                if self.recon_mode == "1":
                    self._goto("recon_scan_setup")
                else:
                    self._start_operation()
            return
        if self.screen == "recon_scan_setup":
            if key in {"LEFT", "RIGHT", "UP", "DOWN"}:
                step = {"LEFT": -1, "RIGHT": 1, "UP": 5, "DOWN": -5}[key]
                self.scan_durations["Recon"] = max(1, min(300, self.scan_durations["Recon"] + step))
                self.dirty = True
            elif key == "TEXT" and char.lower() == "t":
                self.duration_text = str(self.scan_durations["Recon"])
                self.duration_pristine = True
                self._goto("duration_input")
            elif key == "TEXT" and char.isdigit():
                self.duration_text = char
                self.duration_pristine = False
                self._goto("duration_input")
            elif key == "ENTER":
                self.recon_mode = "1"
                self._start_operation()
            return
        if self.screen == "sniffer_live":
            if key in {"UP", "DOWN", "LEFT", "RIGHT"}:
                self.selected = max(0, min(3, self.selected + (-1 if key in {"UP", "LEFT"} else 1)))
                self.dirty = True
            elif key == "ENTER":
                if self.selected == 0:
                    self._stop_sniffer()
                elif self.selected == 1:
                    self._goto("sniffer_probes")
                elif self.selected == 2:
                    self._goto("sniffer_aps")
                else:
                    self.handle("HOME")
            return
        if self.screen == "sniffer_stopped":
            if key in {"UP", "DOWN", "LEFT", "RIGHT"}:
                self.selected = max(0, min(3, self.selected + (-1 if key in {"UP", "LEFT"} else 1)))
                self.dirty = True
            elif key == "ENTER":
                if self.selected == 0:
                    self._goto("sniffer_probes")
                elif self.selected == 1:
                    self._goto("sniffer_aps")
                elif self.selected == 2:
                    self._resume_sniffer()
                else:
                    self._leave_sniffer()
            return
        if self.screen == "sniffer_probes":
            if key in {"UP", "DOWN", "PAGEUP", "PAGEDOWN"}:
                step = {"UP": -1, "DOWN": 1, "PAGEUP": -3, "PAGEDOWN": 3}[key]
                self.selected = max(0, min(max(0, len(self.probe_records) - 1), self.selected + step))
                self.dirty = True
            return
        if self.screen == "sniffer_aps":
            if key in {"UP", "DOWN", "PAGEUP", "PAGEDOWN"}:
                step = {"UP": -1, "DOWN": 1, "PAGEUP": -3, "PAGEDOWN": 3}[key]
                self.selected = max(0, min(max(0, len(self.records) - 1), self.selected + step))
                self.dirty = True
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
                    if self.module:
                        prompt = self.current_prompt.casefold()
                        if self.module.key == "Recon" and not self.workflow_interface_selected and "your choice" in prompt and answer in {"1", "2"}:
                            self.recon_mode = answer
                        elif "select interface" in prompt:
                            self.workflow_interface_selected = True
                    self.awaiting_input = False
                    self.input_value = ""
                    self.choices = []
                    self.back_choice = ""
                self.dirty = True
                return
        if key in {"UP", "DOWN", "PAGEUP", "PAGEDOWN"}:
            step = {"UP": -1, "DOWN": 1, "PAGEUP": -5, "PAGEDOWN": 5}[key]
            if self.screen == "detail" and self.module and self.module.key in SCAN_DEFAULTS:
                self.selected = max(0, min(1, self.selected + step))
                self.dirty = True
                return
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
            if self.module.key in SCAN_DEFAULTS and self.selected == 1:
                self.duration_text = str(self.scan_durations[self.module.key])
                self.duration_pristine = True
                self._goto("duration_input")
            else:
                self._start_operation()
            return
        if self.screen == "detail" and key in {"LEFT", "RIGHT"} and self.module and self.module.key in SCAN_DEFAULTS:
            self.selected = 1 if key == "RIGHT" else 0
            self.dirty = True
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
        self.back_choice = ""
        if self.module.key != "Recon":
            self.recon_mode = ""
        self.recon_choice_sent = False
        self.workflow_interface_selected = False
        self.sniffer_active = False
        self.sniffer_post_choice_ready = False
        self.sniffer_exit_requested = False
        self.probe_records = []
        self.packet_count = 0
        self.probe_total = 0
        self.current_prompt = ""
        self.console.feed(self.logs[0] + "\n")
        self.awaiting_input = False
        self.input_value = ""
        self.follow_output = True
        self._goto("running")

    def _stop_sniffer(self) -> None:
        if self.awaiting_input and self.sniffer_active and self.operation:
            try:
                self.operation.send("")
            except RuntimeError as exc:
                self.error = str(exc)
                self._goto("error")
                return
            self.awaiting_input = False
            self.sniffer_active = False
            self.sniffer_post_choice_ready = False
            self._goto("sniffer_stopped")

    def _resume_sniffer(self) -> None:
        if not self.sniffer_post_choice_ready or not self.awaiting_input or not self.operation:
            return
        try:
            self.operation.send("2")
        except RuntimeError as exc:
            self.error = str(exc)
            self._goto("error")
            return
        self.awaiting_input = False
        self.sniffer_post_choice_ready = False
        self._goto("sniffer_live")

    def _leave_sniffer(self) -> None:
        if not self.sniffer_post_choice_ready or not self.awaiting_input or not self.operation:
            return
        try:
            self.operation.send("0")
        except RuntimeError as exc:
            self.error = str(exc)
            self._goto("error")
            return
        self.awaiting_input = False
        self.sniffer_exit_requested = True
        self.menu = "main"
        self._goto("menu")
