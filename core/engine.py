"""Structured, cancellable API over the existing SwissKnife modules.

The terminal and HAT interfaces keep their current entry points. New front ends
can call this API without copying module code or scraping their CLI output.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .features import FEATURES
from .hardware import HardwareSnapshot, detect_hardware
from .paths import LOG_DIR


@dataclass(frozen=True)
class ModuleInfo:
    key: str
    label: str
    category: str
    description: str
    tools: tuple[str, ...]
    needs_wifi: bool = True
    needs_gps: bool = False
    interactive: bool = True
    enabled: bool = False


_DESCRIPTIONS = {
    "Recon": ("Wi-Fi discovery using the existing Recon parser", ("iw",), False, True),
    "Start Wardrive": ("Wi-Fi survey with GPS and Wigle log", ("iw", "stty"), True, True),
    "ARP scan": ("Connected LAN ping and ARP neighbor discovery", ("ip", "ping"), False, True),
    "IP.CAM finder": ("Camera candidates on the connected LAN", ("ip", "ping"), False, True),
    "Deauth": ("Connection disruption; information only", ("iw", "aireplay-ng"), False, False),
    "Portal": ("Rogue AP and credential collection; information only", ("hostapd", "dnsmasq"), False, False),
    "Evil Twin": ("AP impersonation; information only", ("hostapd", "dnsmasq"), False, False),
    "Handshaker": ("Handshake capture; information only", ("iw", "airodump-ng"), False, False),
    "WiFi Poet": ("Beacon transmission; information only", ("mdk4",), False, False),
    "Dragon Drain": ("WPA3 active workflow; information only", ("iw", "airodump-ng"), False, False),
    "GPS setup": ("GPS diagnostics", ("stty",), True, True),
}

_MONITOR_MODULES = frozenset({"Deauth", "Handshaker", "WiFi Poet", "Dragon Drain"})
_AP_MODULES = frozenset({"Portal", "Evil Twin"})


def available_modules() -> tuple[ModuleInfo, ...]:
    modules = []
    for feature in FEATURES:
        description, tools, gps, enabled = _DESCRIPTIONS.get(
            feature.label,
            (f"{feature.label}: new workflow; integration review required", (), False, False),
        )
        category = "Diagnostics" if feature.label in {"ARP scan", "IP.CAM finder"} else feature.category
        modules.append(ModuleInfo(feature.label, feature.label, category, description, tools, feature.category != "Wardrive" or feature.label == "Start Wardrive", gps, True, enabled))
    return tuple(modules)


def module_status(module: ModuleInfo, hardware: HardwareSnapshot) -> tuple[str, str]:
    if not module.enabled:
        return "unsupported", "Information and compatibility diagnostics only"
    missing = [tool for tool in module.tools if tool not in hardware.tools]
    if missing:
        return "missing_dependency", ", ".join(missing)
    if module.needs_wifi and not hardware.wifi:
        return "missing_hardware", "No Wi-Fi interface"
    if module.needs_gps and not hardware.gps_ports:
        return "missing_hardware", "No GPS serial device"
    return "needs_device_test", "Implemented; physical device not yet verified"


def compatibility_issues(module: ModuleInfo, hardware: HardwareSnapshot) -> tuple[str, ...]:
    """Report prerequisites without implying that an information-only module can run."""
    issues = [f"Missing tool: {tool}" for tool in module.tools if tool not in hardware.tools]
    if module.needs_wifi and not hardware.wifi:
        issues.append("No Wi-Fi interface")
    if module.needs_gps and not hardware.gps_ports:
        issues.append("No GPS serial device")
    if module.key in _MONITOR_MODULES:
        if not any(item.monitor_supported is True for item in hardware.wifi):
            issues.append("Monitor-mode adapter not confirmed")
    if module.key in _AP_MODULES:
        issues.append("AP-mode capability not verified")
    return tuple(issues)


@dataclass(frozen=True)
class EngineEvent:
    kind: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


class Operation:
    def __init__(self, key: str, config: dict[str, Any], *, log_path: Path | None = None) -> None:
        self.key = key
        self.config = config
        self.events: queue.Queue[EngineEvent] = queue.Queue()
        self.cancelled = threading.Event()
        self.thread: threading.Thread | None = None
        self.state = "starting"
        self.log_path = log_path
        self._log_lock = threading.Lock()

    def emit(self, kind: str, message: str, **data: Any) -> None:
        self.events.put(EngineEvent(kind, message, data))
        if self.log_path is not None:
            try:
                with self._log_lock, self.log_path.open("a", encoding="utf-8") as handle:
                    handle.write(f"{datetime.now().isoformat(timespec='seconds')} [{kind}] {message}\n")
            except OSError:
                pass

    def cancel(self) -> None:
        self.cancelled.set()
        self.emit("status", "Cancellation requested")

    def poll(self) -> list[EngineEvent]:
        events = []
        while True:
            try:
                events.append(self.events.get_nowait())
            except queue.Empty:
                return events


class SwissKnifeEngine:
    def __init__(self, *, demo: bool = False) -> None:
        self.demo = demo
        self._modules = {item.key: item for item in available_modules()}

    def hardware(self) -> HardwareSnapshot:
        if self.demo:
            from .hardware import WiFiAdapter
            return HardwareSnapshot(("wlan0", "wlan1"), (WiFiAdapter("wlan0", "demo built-in", "managed", False, None), WiFiAdapter("wlan1", "demo USB", "managed", True, True)), ("[SIMULATED] USB Wi-Fi", "[SIMULATED] GPS"), ("/dev/demo-gps",), "wlan0", False, frozenset({tool for module in self._modules.values() for tool in module.tools}))
        return detect_hardware()

    def modules(self) -> tuple[ModuleInfo, ...]:
        return tuple(self._modules.values())

    def start(self, key: str, config: dict[str, Any], *, hardware: HardwareSnapshot | None = None) -> Operation:
        module = self._modules.get(key)
        if module is None:
            raise ValueError("Unknown module")
        if not module.enabled:
            raise PermissionError("This module has no Cardputer Zero execution path")
        hardware = hardware or self.hardware()
        status, reason = module_status(module, hardware)
        if status in {"missing_dependency", "missing_hardware", "unsupported"}:
            raise RuntimeError(reason)
        interface = str(config.get("interface", ""))
        if module.needs_wifi and interface not in {item.name for item in hardware.wifi}:
            raise ValueError("Select an available Wi-Fi interface")
        if module.key in {"Recon", "Start Wardrive"} and interface:
            adapter = next(item for item in hardware.wifi if item.name == interface)
            if adapter.mode != "managed":
                raise RuntimeError("Select an interface already in managed mode; the GUI will not change its mode")
        if module.needs_wifi and interface == hardware.default_route and config.get("allow_management_interface") is not True:
            raise PermissionError("Confirm use of the management interface before starting")
        duration = int(config.get("duration", 5))
        if not 1 <= duration <= 60:
            raise ValueError("Duration must be between 1 and 60 seconds")
        log_path = None
        if not self.demo:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            log_path = LOG_DIR / f"cardputer-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{key.lower().replace(' ', '-')}.log"
        max_hosts = int(config.get("max_hosts", 64))
        if not 32 <= max_hosts <= 128:
            raise ValueError("Host limit must be between 32 and 128")
        operation = Operation(key, {**config, "duration": duration, "max_hosts": max_hosts}, log_path=log_path)
        operation.thread = threading.Thread(target=self._run, args=(operation,), daemon=True)
        operation.thread.start()
        return operation

    def _run(self, operation: Operation) -> None:
        operation.state = "running"
        operation.emit("status", "[SIMULATED] Running" if self.demo else "Running")
        try:
            if self.demo:
                self._demo_run(operation)
            elif operation.key == "Recon":
                self._recon(operation)
            elif operation.key == "Start Wardrive":
                self._wardrive(operation)
            elif operation.key == "ARP scan":
                self._arp(operation)
            elif operation.key == "IP.CAM finder":
                self._ipcam(operation)
            elif operation.key == "GPS setup":
                self._gps(operation)
            operation.state = "cancelled" if operation.cancelled.is_set() else "completed"
            operation.emit("finished", operation.state)
        except Exception as exc:
            operation.state = "error"
            operation.emit("error", f"{type(exc).__name__}: {exc}")

    def _demo_run(self, operation: Operation) -> None:
        samples = {"Recon": ["[SIMULATED] LAB5-TEST  -51 dBm  ch 6", "[SIMULATED] GUEST-TEST  -72 dBm  ch 11"], "Start Wardrive": ["[SIMULATED] GPS fix 52.2300, 21.0100", "[SIMULATED] 2 networks logged"], "ARP scan": ["[SIMULATED] 192.0.2.10  02:00:00:00:00:10"], "IP.CAM finder": ["[SIMULATED] 192.0.2.20  camera candidate"], "GPS setup": ["[SIMULATED] GPS fix available"]}
        for line in samples.get(operation.key, []):
            if operation.cancelled.wait(0.15):
                return
            operation.emit("result", line, simulated=True)

    def _recon(self, operation: Operation) -> None:
        from modules import recon
        interface = operation.config["interface"]
        networks = recon.scan_wireless_networks_iw(interface, operation.config["duration"], cancel_event=operation.cancelled, allow_mode_change=False, raise_on_error=True)
        if operation.cancelled.is_set():
            return
        query = str(operation.config.get("filter", "")).casefold().strip()
        for item in networks:
            if operation.cancelled.is_set():
                return
            if query and query not in str(item.get("ssid") or "").casefold():
                continue
            operation.emit("result", f"{item.get('ssid') or '<hidden>'}  {item.get('signal')} dBm  ch {item.get('channel')}", **item)
        operation.emit("progress", f"{len(networks)} networks found")

    def _gps(self, operation: Operation) -> None:
        from modules import wardrive
        device, fix = wardrive.detect_gps(verbose=False, cancel_event=operation.cancelled)
        if operation.cancelled.is_set():
            return
        if not device or fix is None:
            raise RuntimeError("GPS receiver has no valid fix")
        operation.emit("result", f"{device}: {fix.latitude:.6f}, {fix.longitude:.6f}", latitude=fix.latitude, longitude=fix.longitude)

    def _wardrive(self, operation: Operation) -> None:
        from modules import wardrive
        device, fix = wardrive.detect_gps(verbose=False, cancel_event=operation.cancelled)
        if operation.cancelled.is_set():
            return
        if not device or fix is None:
            raise RuntimeError("GPS receiver has no valid fix")
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        path = wardrive.next_wardrive_log_path(str(LOG_DIR))
        wardrive.create_wigle_log(path)
        operation.emit("status", f"Writing {path}")
        cycles = max(1, min(100, int(operation.config.get("cycles", 3))))
        for index in range(cycles):
            if operation.cancelled.is_set():
                return
            networks = wardrive.scan_networks_once(operation.config["interface"], timeout_seconds=min(7, operation.config["duration"]), cancel_event=operation.cancelled, raise_on_error=True)
            if operation.cancelled.is_set():
                return
            query = str(operation.config.get("filter", "")).casefold().strip()
            if query:
                networks = [item for item in networks if query in item.ssid.casefold()]
            fix, _ = wardrive.probe_gps_device(device, cancel_event=operation.cancelled)
            if operation.cancelled.is_set():
                return
            if fix is None:
                operation.emit("progress", "GPS fix lost; no rows saved")
                continue
            count = wardrive.append_wigle_rows(path, networks, fix, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            operation.emit("progress", f"Cycle {index + 1}/{cycles}: {count} rows", count=count, path=path)

    def _arp(self, operation: Operation) -> None:
        from modules.arp_scanner import ArpScanner, load_oui_database
        scanner = ArpScanner(interface=operation.config["interface"], max_hosts=operation.config["max_hosts"], rounds=1)
        scanner.running = True
        scanner._stop_event = operation.cancelled
        scanner._vendors_by_oui = load_oui_database(scanner.oui_db)
        subnet = scanner._get_interface_subnet(scanner.interface)
        if subnet is None or subnet.num_addresses > 4096:
            raise RuntimeError("Connected IPv4 subnet missing or too large")
        hosts = scanner._hosts_for_sweep(scanner.interface, subnet)
        operation.emit("progress", f"Checking up to {len(hosts)} hosts in {subnet}")
        scanner._ping_sweep(scanner.interface, hosts, workers=16)
        if operation.cancelled.is_set():
            return
        for item in scanner._read_ip_neighbors(scanner.interface):
            operation.emit("result", f"{item.ip}  {item.mac}  {item.vendor}", ip=item.ip, mac=item.mac, vendor=item.vendor)

    def _ipcam(self, operation: Operation) -> None:
        from modules.ipcam_finder import IpCamFinder
        finder = IpCamFinder(interface=operation.config["interface"], max_hosts=operation.config["max_hosts"], rounds=1)
        finder.running = True
        finder._stop_event = operation.cancelled
        subnet = finder._get_interface_subnet(finder.interface)
        if subnet is None or subnet.num_addresses > 4096:
            raise RuntimeError("Connected IPv4 subnet missing or too large")
        hosts = finder._hosts_for_sweep(finder.interface, subnet)
        operation.emit("progress", f"Checking up to {len(hosts)} hosts in {subnet}")
        finder._ping_sweep(finder.interface, hosts, workers=16)
        if operation.cancelled.is_set():
            return
        finder._ingest_neighbors(finder.interface)
        for item in finder._camera_hits.values():
            operation.emit("result", f"{item.ip}  {item.vendor}  {item.mac}", ip=item.ip, mac=item.mac, vendor=item.vendor)
