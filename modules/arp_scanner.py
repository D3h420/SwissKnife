#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    RICH_AVAILABLE = True
except ModuleNotFoundError:
    # Keep the module usable even when rich is not installed.
    RICH_AVAILABLE = False

    class _FallbackStatus:
        def __init__(self, message: str) -> None:
            self.message = message

        def __enter__(self) -> None:
            if self.message:
                print(self.message)
            return None

        def __exit__(self, _exc_type, _exc, _tb) -> bool:
            return False

    class Console:  # type: ignore[override]
        def print(self, *objects: object, **_kwargs: object) -> None:
            print(*objects)

        def status(self, message: str):
            return _FallbackStatus(message)

    class _FallbackBox:
        SIMPLE_HEAVY = None

    box = _FallbackBox()  # type: ignore[assignment]

    class Panel:  # type: ignore[override]
        def __init__(self, renderable: object, title: str = "", subtitle: str = "", border_style: str = "") -> None:
            self.renderable = renderable
            self.title = title
            self.subtitle = subtitle
            self.border_style = border_style

        @classmethod
        def fit(cls, renderable: object, **kwargs: object):
            return cls(renderable, **kwargs)

        def __str__(self) -> str:
            heading = self.title or self.subtitle
            if heading:
                return f"{heading}\n{self.renderable}"
            return str(self.renderable)

    class Table:  # type: ignore[override]
        def __init__(self, title: str = "", box: object = None) -> None:
            self.title = title
            self.columns: List[str] = []
            self.rows: List[List[str]] = []

        def add_column(self, name: str, **_kwargs: object) -> None:
            self.columns.append(name)

        def add_row(self, *values: object) -> None:
            self.rows.append([str(value) for value in values])

        def __str__(self) -> str:
            parts: List[str] = []
            if self.title:
                parts.append(self.title)
            if self.columns:
                parts.append(" | ".join(self.columns))
            for row in self.rows:
                parts.append(" | ".join(row))
            return "\n".join(parts)

    class Prompt:  # type: ignore[override]
        @staticmethod
        def ask(prompt: str, default: str = "", password: bool = False, console: Optional[Console] = None) -> str:
            del console
            if password:
                try:
                    import getpass

                    value = getpass.getpass(f"{prompt}: ")
                except Exception:
                    value = ""
                if value:
                    return value
                return default

            sys.stdout.write(f"{prompt}")
            if default:
                sys.stdout.write(f" [{default}]")
            sys.stdout.write(": ")
            sys.stdout.flush()
            raw = sys.stdin.readline()
            value = (raw or "").strip()
            return value or default

try:
    from core.module import Module  # type: ignore
except Exception:
    class Module:
        """Fallback base for branches without core.module."""

        def __init__(self, name: str = "Module") -> None:
            self.name = name
            self.console = Console()
            self.status = "idle"
            self.running = False

        def stop(self) -> None:
            self.running = False
            self.status = "stopped"


MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUI_DB = os.environ.get("SWISSKNIFE_VENDOR_DB", os.path.join(MODULE_DIR, "oui.txt"))

MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
HEXLEN_RE = re.compile(r"[^0-9A-Fa-f]")
IP_NEIGH_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+"
    r"(?P<state>\S+)"
)
ARP_SCAN_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})"
    r"(?:\s+(?P<vendor>.*))?$"
)


@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str
    signal: Optional[int]
    channel: Optional[int]
    security: str


@dataclass
class ArpDevice:
    ip: str
    mac: str
    vendor: str
    state: str
    source: str = "ARP"


@dataclass
class InterfaceProfile:
    name: str
    role: str
    chipset: str
    mode: str
    state: str


def run_command(args: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args=args,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )


def tool_exists(tool: str) -> bool:
    return subprocess.run(
        ["which", tool],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def normalize_mac(mac: str) -> str:
    return mac.strip().upper()


def normalize_oui_key(value: str) -> str:
    cleaned = HEXLEN_RE.sub("", value or "").upper()
    if len(cleaned) < 6:
        return ""
    return cleaned[:6]


def nmcli_unescape(value: str) -> str:
    buf: List[str] = []
    escape = False
    for char in value:
        if escape:
            buf.append(char)
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        buf.append(char)
    return "".join(buf)


def split_nmcli_escaped(line: str, expected: int) -> List[str]:
    fields: List[str] = []
    current: List[str] = []
    escape = False
    for char in line:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == ":" and len(fields) < expected - 1:
            fields.append("".join(current))
            current = []
            continue
        current.append(char)
    fields.append("".join(current))
    if len(fields) < expected:
        fields.extend([""] * (expected - len(fields)))
    return fields[:expected]


def load_oui_database(path: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not path or not os.path.isfile(path):
        return mapping
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = re.split(r"\s+", line, maxsplit=1)
                if len(parts) != 2:
                    continue
                prefix = normalize_oui_key(parts[0])
                vendor = parts[1].strip()
                if prefix and vendor:
                    mapping[prefix] = vendor
    except OSError:
        return {}
    return mapping


class ArpScanner(Module):
    def __init__(
        self,
        interface: str = "auto",
        preferred_ssid: str = "",
        password: str = "",
        scan_duration: int = 0,
        rounds: int = 2,
        max_hosts: int = 384,
        ping_timeout: float = 0.8,
        oui_db: str = DEFAULT_OUI_DB,
    ) -> None:
        super().__init__(name="ARP scanner")
        self.interface = (interface or "auto").strip()
        self.preferred_ssid = preferred_ssid.strip()
        self.password = password
        self.scan_duration = max(0, int(scan_duration))
        self.rounds = max(1, int(rounds))
        self.max_hosts = max(32, int(max_hosts))
        self.ping_timeout = max(0.1, float(ping_timeout))
        self.oui_db = oui_db

        self.status = "idle"
        self.running = False
        self._stop_event = threading.Event()
        self._signal_handlers: Dict[int, object] = {}
        self._selected_interface: str = ""
        self._connected_interface: str = ""
        self._interface_profiles: Dict[str, InterfaceProfile] = {}
        self._target_network: Optional[WiFiNetwork] = None
        self._connected_subnet: str = ""
        self._devices_by_ip: Dict[str, ArpDevice] = {}
        self._vendors_by_oui: Dict[str, str] = {}
        self._error: Optional[str] = None
        self._wpa_managed_interface: str = ""
        self._wpa_pid_file: str = ""
        self._wpa_ctrl_dir: str = ""

    def run(self) -> None:
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()

        self.console.print("[cyan]ARP Scanner Wizard[/cyan]")
        self.console.print("Wi-Fi join + LAN ARP discovery")
        self.console.print("")

        try:
            self._ensure_runtime_requirements()
            self._vendors_by_oui = load_oui_database(self.oui_db)

            interface = self._select_interface()
            self._selected_interface = interface
            self._ensure_client_mode(interface)
            scan_duration = self._resolve_scan_duration()

            networks = self._scan_wifi_networks(interface, scan_duration)
            if not networks:
                raise RuntimeError("No Wi-Fi networks detected on selected interface.")

            self._render_networks_table(networks)
            target = self._choose_target_network(networks)
            self._target_network = target

            password = self._resolve_password_for_network(target)
            self._connect_to_network(interface, target, password)

            connected_interface, subnet = self._resolve_connected_interface_and_subnet(
                interface,
                target,
                timeout=28.0,
            )
            if not subnet:
                raise RuntimeError(
                    "Connected, but no IPv4 subnet detected. Check DHCP or static IP settings."
                )
            if connected_interface != interface:
                self.console.print(
                    f"[yellow]Connection moved to {connected_interface}; continuing on that interface.[/yellow]"
                )
            interface = connected_interface
            self._selected_interface = interface
            self._connected_interface = interface
            self._connected_subnet = str(subnet)

            self.console.print(
                "[bold cyan]ARP table scan in progress... (Ctrl+C to stop)[/bold cyan]\n"
                f"[dim]Interface:[/dim] {interface}  "
                f"[dim]Network:[/dim] {target.ssid or '<hidden>'}  "
                f"[dim]Subnet:[/dim] {subnet}"
            )

            with self.console.status("[bold cyan]Discovering ARP entries...[/bold cyan]"):
                self._collect_arp_entries(interface, subnet)

            self.status = "completed"
        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]Interrupted by user.[/yellow]")
        except Exception as exc:
            self._error = str(exc)
            self.status = "error"
            self.console.print(f"[red]ARP scanner error:[/red] {exc}")
        finally:
            self.running = False
            self._stop_event.set()
            elapsed = max(0, int(time.time() - started))
            if self._wpa_managed_interface:
                self._cleanup_wpa_runtime(self._wpa_managed_interface, restore_managed=True)
            self._render_summary(elapsed)
            if self._selected_interface:
                run_command(["nmcli", "device", "set", self._selected_interface, "managed", "yes"], timeout=8.0)
            self._restore_signal_handlers()

    def stop(self) -> None:
        self.running = False
        self.status = "stopped"
        self._stop_event.set()
        self.console.print("[yellow]Stopping ARP scanner...[/yellow]")

    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._signal_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handle_signal)
            except Exception:
                continue

    def _restore_signal_handlers(self) -> None:
        for sig, handler in self._signal_handlers.items():
            try:
                signal.signal(sig, handler)
            except Exception:
                continue

    def _handle_signal(self, _sig: int, _frame: object) -> None:
        self.stop()

    def _ensure_runtime_requirements(self) -> None:
        if os.geteuid() != 0:
            raise RuntimeError("ARP scanner must run as root.")
        required = ["iw", "ip", "nmcli", "ping", "arp-scan"]
        missing = [tool for tool in required if not tool_exists(tool)]
        if missing:
            raise RuntimeError(f"Missing required tools: {', '.join(missing)}")

    def _list_wifi_interfaces(self) -> List[str]:
        result = run_command(["iw", "dev"], timeout=3.0)
        interfaces: List[str] = []
        if result.returncode == 0:
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if line.startswith("Interface "):
                    name = line.split("Interface", 1)[1].strip()
                    if name and name != "lo":
                        interfaces.append(name)

        if interfaces:
            return sorted(set(interfaces))

        fallback = run_command(["ip", "-o", "link", "show"], timeout=3.0)
        if fallback.returncode == 0:
            for raw_line in fallback.stdout.splitlines():
                if ": " not in raw_line:
                    continue
                name = raw_line.split(": ", 1)[1].split(":", 1)[0]
                if name.startswith("wl"):
                    interfaces.append(name)
        return sorted(set(interfaces))

    def _get_interface_chipset(self, interface: str) -> str:
        if not tool_exists("ethtool"):
            return "unknown"
        result = run_command(["ethtool", "-i", interface], timeout=3.0)
        if result.returncode != 0:
            return "unknown"

        driver = ""
        bus_info = ""
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("driver:"):
                driver = line.split(":", 1)[1].strip()
            elif line.startswith("bus-info:"):
                bus_info = line.split(":", 1)[1].strip()

        if driver and bus_info:
            return f"{driver} ({bus_info})"
        if driver:
            return driver
        return "unknown"

    def _get_interface_mode(self, interface: str) -> str:
        result = run_command(["iw", "dev", interface, "info"], timeout=3.0)
        if result.returncode != 0:
            return "unknown"
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("type "):
                return line.split("type", 1)[1].strip()
        return "unknown"

    def _is_interface_up(self, interface: str) -> bool:
        result = run_command(["ip", "link", "show", "dev", interface], timeout=3.0)
        if result.returncode != 0:
            return False
        output = result.stdout
        if "state UP" in output:
            return True
        if "<" in output and ">" in output:
            flags = output.split("<", 1)[1].split(">", 1)[0]
            return "UP" in flags.split(",")
        return False

    def _classify_interface_role(self, interface: str, chipset: str) -> str:
        probe = f"{interface} {chipset}".lower()
        if "usb" in probe:
            return "External USB"
        if "platform" in probe or "sdio" in probe:
            return "Built-in"
        if "pci" in probe:
            return "Internal PCIe"
        if interface == "wlan0":
            return "Built-in"
        return "Unknown"

    def _build_interface_profiles(self, interfaces: List[str]) -> Dict[str, InterfaceProfile]:
        profiles: Dict[str, InterfaceProfile] = {}
        for iface in interfaces:
            chipset = self._get_interface_chipset(iface)
            mode = self._get_interface_mode(iface)
            state = "UP" if self._is_interface_up(iface) else "DOWN"
            role = self._classify_interface_role(iface, chipset)
            profiles[iface] = InterfaceProfile(
                name=iface,
                role=role,
                chipset=chipset,
                mode=mode,
                state=state,
            )
        return profiles

    @staticmethod
    def _is_client_capable_mode(mode: str) -> bool:
        return (mode or "").strip().lower() in {"managed", "unknown"}

    def _interface_sort_key(self, iface: str) -> Tuple[int, str]:
        profile = self._interface_profiles.get(iface)
        mode = (profile.mode if profile else "").strip().lower()
        if mode == "managed":
            rank = 0
        elif mode == "unknown":
            rank = 1
        elif mode in {"ap", "master"}:
            rank = 3
        elif mode == "monitor":
            rank = 4
        else:
            rank = 2
        return rank, iface

    def _select_interface(self) -> str:
        interfaces = self._list_wifi_interfaces()
        if not interfaces:
            raise RuntimeError("No Wi-Fi interfaces found.")
        self._interface_profiles = self._build_interface_profiles(interfaces)

        ordered = sorted(
            interfaces,
            key=self._interface_sort_key,
        )

        if self.interface and self.interface != "auto":
            if self.interface not in ordered:
                raise RuntimeError(f"Interface '{self.interface}' is not available.")
            profile = self._interface_profiles.get(self.interface)
            mode = profile.mode if profile else self._get_interface_mode(self.interface)
            if not self._is_client_capable_mode(mode):
                raise RuntimeError(
                    f"Interface '{self.interface}' is in {mode.upper()} mode. "
                    "Select a managed client interface for ARP scan."
                )
            return self.interface

        if len(ordered) == 1:
            profile = self._interface_profiles.get(ordered[0])
            if profile:
                display_name = f"{profile.name} (AP running)" if profile.name == "wlan0" else profile.name
                self.console.print(
                    f"[green]Selected interface:[/green] {display_name} "
                    f"([dim]{profile.role} | {profile.chipset}[/dim])"
                )
            else:
                display_name = f"{ordered[0]} (AP running)" if ordered[0] == "wlan0" else ordered[0]
                self.console.print(f"[green]Selected interface:[/green] {display_name}")
            return ordered[0]

        self.console.print("")
        self.console.print("[bold]Available interfaces:[/bold]")
        for idx, iface in enumerate(ordered, start=1):
            profile = self._interface_profiles.get(iface)
            if not profile:
                display_name = f"{iface} (AP running)" if iface == "wlan0" else iface
                self.console.print(f"  {idx}) {display_name} - unknown [unknown]")
                continue
            display_name = f"{profile.name} (AP running)" if profile.name == "wlan0" else profile.name
            details = f"{profile.chipset} [{profile.mode.lower()} | {profile.state}]"
            self.console.print(
                f"  [magenta]{idx}) {display_name} -[/magenta] {details}"
            )

        while self.running:
            raw = Prompt.ask("Select interface (number)", default="1", console=self.console)
            try:
                picked = int(raw)
            except ValueError:
                self.console.print("[yellow]Enter a numeric interface index.[/yellow]")
                continue
            if 1 <= picked <= len(ordered):
                chosen = ordered[picked - 1]
                profile = self._interface_profiles.get(chosen)
                mode = profile.mode if profile else self._get_interface_mode(chosen)
                if not self._is_client_capable_mode(mode):
                    self.console.print(
                        f"[red]Interface {chosen} is in {mode.upper()} mode and cannot join Wi-Fi as client.[/red]"
                    )
                    continue
                return chosen
            self.console.print("[yellow]Invalid index.[/yellow]")

        raise KeyboardInterrupt

    def _resolve_scan_duration(self) -> int:
        if self.scan_duration > 0:
            self.console.print(
                f"[green]Using scan duration from args:[/green] {self.scan_duration}s"
            )
            return self.scan_duration

        raw = Prompt.ask("Scan duration in seconds", default="15", console=self.console).strip()
        try:
            value = int(raw) if raw else 15
        except ValueError:
            self.console.print("[yellow]Invalid duration. Using 15 seconds.[/yellow]")
            value = 15
        if value < 1:
            self.console.print("[yellow]Scan duration too short. Using 1 second.[/yellow]")
            value = 1
        return value

    @staticmethod
    def _merge_network_rows(rows: Dict[str, WiFiNetwork], fresh_rows: List[WiFiNetwork]) -> None:
        for entry in fresh_rows:
            existing = rows.get(entry.bssid)
            if not existing:
                rows[entry.bssid] = entry
                continue
            old_signal = existing.signal if existing.signal is not None else -999
            new_signal = entry.signal if entry.signal is not None else -999
            if new_signal > old_signal:
                rows[entry.bssid] = entry

    @staticmethod
    def _is_transient_scan_error(error_text: str) -> bool:
        lower = (error_text or "").lower()
        return (
            "network is down" in lower
            or "resource busy" in lower
            or "device or resource busy" in lower
            or "temporary failure" in lower
        )

    def _recover_scan_interface(self, interface: str) -> None:
        run_command(["nmcli", "radio", "wifi", "on"], timeout=8.0)
        run_command(["nmcli", "device", "set", interface, "managed", "yes"], timeout=8.0)
        run_command(["ip", "link", "set", interface, "up"], timeout=5.0)
        time.sleep(0.6)

    def _scan_wifi_networks(self, interface: str, duration_seconds: int) -> List[WiFiNetwork]:
        duration_seconds = max(1, int(duration_seconds))
        self.console.print(f"[cyan]Scanning nearby Wi-Fi on {interface} for {duration_seconds}s...[/cyan]")
        self._prepare_network_manager(interface)

        deadline = time.time() + duration_seconds
        rows: Dict[str, WiFiNetwork] = {}
        last_error = ""
        while time.time() < deadline and self.running:
            nmcli_rows, nmcli_error = self._scan_wifi_networks_nmcli(interface)
            self._merge_network_rows(rows, nmcli_rows)
            if nmcli_error:
                last_error = nmcli_error

            iw_rows, iw_error = self._scan_wifi_networks_iw(interface)
            self._merge_network_rows(rows, iw_rows)
            if iw_error:
                last_error = iw_error
                if self._is_transient_scan_error(iw_error):
                    self._recover_scan_interface(interface)

            remaining = deadline - time.time()
            if remaining > 0:
                time.sleep(min(1.0, remaining))

        ordered = list(rows.values())
        ordered.sort(key=lambda item: item.signal if item.signal is not None else -999, reverse=True)
        if ordered:
            return ordered
        if last_error:
            raise RuntimeError(last_error)
        return []

    def _scan_wifi_networks_nmcli(self, interface: str) -> Tuple[List[WiFiNetwork], str]:
        rescan = run_command(["nmcli", "device", "wifi", "rescan", "ifname", interface], timeout=10.0)
        if rescan.returncode != 0:
            err = (rescan.stderr or rescan.stdout or "").strip()
            return [], err
        time.sleep(1.0)
        result = run_command(
            [
                "nmcli",
                "-t",
                "--escape",
                "yes",
                "-f",
                "SSID,BSSID,SIGNAL,CHAN,SECURITY",
                "device",
                "wifi",
                "list",
                "ifname",
                interface,
            ],
            timeout=12.0,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            return [], err

        rows: Dict[str, WiFiNetwork] = {}
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            ssid_raw, bssid_raw, signal_raw, channel_raw, security_raw = split_nmcli_escaped(line, 5)
            bssid = normalize_mac(nmcli_unescape(bssid_raw))
            if not MAC_RE.fullmatch(bssid):
                continue

            ssid_value = nmcli_unescape(ssid_raw).strip()
            security_value = nmcli_unescape(security_raw).strip() or "OPEN"
            if security_value in {"--", "(none)"}:
                security_value = "OPEN"
            elif "WPA" in security_value.upper():
                security_value = "WPA/WPA2"

            signal: Optional[int] = None
            channel: Optional[int] = None
            try:
                if signal_raw:
                    signal = int(float(nmcli_unescape(signal_raw)))
            except ValueError:
                signal = None
            try:
                if channel_raw:
                    channel = int(float(nmcli_unescape(channel_raw)))
            except ValueError:
                channel = None

            entry = WiFiNetwork(
                ssid=ssid_value if ssid_value else "<hidden>",
                bssid=bssid,
                signal=signal,
                channel=channel,
                security=security_value,
            )
            self._merge_network_rows(rows, [entry])

        ordered = list(rows.values())
        ordered.sort(key=lambda item: item.signal if item.signal is not None else -999, reverse=True)
        return ordered, ""

    def _scan_wifi_networks_iw(self, interface: str) -> Tuple[List[WiFiNetwork], str]:
        result = run_command(["iw", "dev", interface, "scan"], timeout=25.0)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return [], stderr or "Wi-Fi scan failed."

        rows: Dict[str, WiFiNetwork] = {}
        current: Dict[str, object] = {}

        def flush_current() -> None:
            bssid = str(current.get("bssid") or "").upper()
            if not MAC_RE.fullmatch(bssid):
                return
            entry = WiFiNetwork(
                ssid=str(current.get("ssid") or "<hidden>"),
                bssid=bssid,
                signal=current.get("signal") if isinstance(current.get("signal"), int) else None,
                channel=current.get("channel") if isinstance(current.get("channel"), int) else None,
                security=str(current.get("security") or "OPEN"),
            )
            self._merge_network_rows(rows, [entry])

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                flush_current()
                token = line.split()[1]
                bssid = token.split("(", 1)[0].strip().upper()
                current = {
                    "bssid": bssid,
                    "ssid": "<hidden>",
                    "signal": None,
                    "channel": None,
                    "security": "OPEN",
                }
                continue

            if not current:
                continue

            if line.startswith("SSID:"):
                ssid = line.split("SSID:", 1)[1].strip()
                current["ssid"] = ssid if ssid else "<hidden>"
                continue

            if line.startswith("signal:"):
                signal_raw = line.split("signal:", 1)[1].strip().split()[0]
                try:
                    current["signal"] = int(float(signal_raw))
                except ValueError:
                    pass
                continue

            if line.startswith("DS Parameter set: channel"):
                try:
                    current["channel"] = int(line.rsplit(" ", 1)[1])
                except ValueError:
                    pass
                continue

            if line.startswith("freq:") and not current.get("channel"):
                try:
                    freq = int(line.split("freq:", 1)[1].strip())
                except ValueError:
                    continue
                channel = self._freq_to_channel(freq)
                if channel:
                    current["channel"] = channel
                continue

            if line.startswith("RSN:") or line.startswith("WPA:"):
                current["security"] = "WPA/WPA2"
                continue

            if line.startswith("capability:") and "Privacy" in line and current.get("security") == "OPEN":
                current["security"] = "WEP/Protected"

        flush_current()

        ordered = list(rows.values())
        ordered.sort(key=lambda item: item.signal if item.signal is not None else -999, reverse=True)
        return ordered, ""

    def _render_networks_table(self, networks: List[WiFiNetwork]) -> None:
        table = Table(title="Nearby Wi-Fi Networks", box=box.SIMPLE_HEAVY)
        table.add_column("#", justify="right", style="cyan", no_wrap=True)
        table.add_column("SSID", style="bold")
        table.add_column("BSSID", style="magenta")
        table.add_column("RSSI", justify="right")
        table.add_column("CH", justify="right")
        table.add_column("Sec")
        table.add_column("AP Vendor")

        for idx, net in enumerate(networks, start=1):
            rssi = f"{net.signal} dBm" if net.signal is not None else "?"
            ch = str(net.channel) if net.channel is not None else "?"
            vendor = self._lookup_vendor(net.bssid)
            table.add_row(
                str(idx),
                net.ssid or "<hidden>",
                net.bssid,
                rssi,
                ch,
                net.security,
                vendor,
            )
        self.console.print(table)

    def _choose_target_network(self, networks: List[WiFiNetwork]) -> WiFiNetwork:
        if self.preferred_ssid:
            for network in networks:
                if network.ssid == self.preferred_ssid:
                    self.console.print(f"[green]Selected preferred SSID:[/green] {self.preferred_ssid}")
                    return network
            self.console.print(
                f"[yellow]Preferred SSID '{self.preferred_ssid}' not found. Falling back to manual selection.[/yellow]"
            )

        while self.running:
            raw = Prompt.ask("Choose network number", default="1", console=self.console)
            try:
                idx = int(raw)
            except ValueError:
                self.console.print("[yellow]Enter a numeric network index.[/yellow]")
                continue
            if 1 <= idx <= len(networks):
                picked = networks[idx - 1]
                self.console.print(
                    f"[green]Target network:[/green] {picked.ssid or '<hidden>'} ({picked.bssid})"
                )
                return picked
            self.console.print("[yellow]Invalid index.[/yellow]")

        raise KeyboardInterrupt

    def _resolve_password_for_network(self, network: WiFiNetwork) -> str:
        secure = network.security.upper() != "OPEN"
        if not secure:
            return ""
        if self.password:
            return self.password
        return Prompt.ask(
            f"Password for [bold]{network.ssid or network.bssid}[/bold]",
            password=False,
            console=self.console,
        )

    def _connect_to_network(self, interface: str, network: WiFiNetwork, password: str) -> None:
        self.console.print(f"[cyan]Connecting {interface} to {network.ssid or network.bssid}...[/cyan]")
        self._prepare_network_manager(interface)

        clean_ssid = (network.ssid or "").strip()
        ssid_target = clean_ssid if clean_ssid and clean_ssid != "<hidden>" else ""
        attempts: List[List[str]] = []
        bssid_visible = self._is_bssid_visible(interface, network.bssid)

        if ssid_target:
            cmd_no_bssid = ["nmcli", "--wait", "30", "device", "wifi", "connect", ssid_target, "ifname", interface]
            if password:
                cmd_no_bssid += ["password", password]
            attempts.append(cmd_no_bssid)

            if bssid_visible:
                cmd_with_bssid = ["nmcli", "--wait", "30", "device", "wifi", "connect", ssid_target, "ifname", interface]
                if password:
                    cmd_with_bssid += ["password", password]
                cmd_with_bssid += ["bssid", network.bssid]
                attempts.append(cmd_with_bssid)

        if bssid_visible:
            cmd_bssid = ["nmcli", "--wait", "30", "device", "wifi", "connect", network.bssid, "ifname", interface]
            if password:
                cmd_bssid += ["password", password]
            attempts.append(cmd_bssid)
        elif not ssid_target:
            raise RuntimeError(
                f"Target BSSID {network.bssid} is not visible on {interface}. "
                "Select network again or move closer to AP."
            )

        last_error = ""
        errors: List[str] = []
        for cmd in attempts:
            run_command(["nmcli", "device", "wifi", "rescan", "ifname", interface], timeout=8.0)
            time.sleep(1.2)
            result = run_command(cmd, timeout=35.0)
            if result.returncode == 0:
                self.console.print("[green]Wi-Fi connected.[/green]")
                return
            last_error = (result.stderr or result.stdout or "").strip()
            if last_error:
                errors.append(last_error)

        if ssid_target:
            run_command(["nmcli", "device", "wifi", "rescan", "ifname", interface], timeout=8.0)
            time.sleep(1.2)
            profile_error = self._connect_via_temp_profile(interface, ssid_target, password, network.bssid if bssid_visible else "")
            if not profile_error:
                self.console.print("[green]Wi-Fi connected.[/green]")
                return
            errors.append(profile_error)

            supp_error = self._connect_with_wpa_supplicant(interface, ssid_target, password, network.bssid if bssid_visible else "")
            if not supp_error:
                self.console.print("[green]Wi-Fi connected via wpa_supplicant fallback.[/green]")
                return
            errors.append(supp_error)

        if errors:
            deduped = []
            for item in errors:
                if item not in deduped:
                    deduped.append(item)
            hint = self._build_visibility_hint(interface, ssid_target, network.bssid)
            message = deduped[-1]
            if hint:
                message = f"{message} ({hint})"
            raise RuntimeError(message)
        raise RuntimeError(last_error or "Failed to connect to selected Wi-Fi network.")

    def _connect_via_temp_profile(self, interface: str, ssid: str, password: str, bssid: str) -> str:
        profile = f"swissknife-{interface}-arp"
        run_command(["nmcli", "connection", "delete", profile], timeout=6.0)

        add_cmd = ["nmcli", "connection", "add", "type", "wifi", "ifname", interface, "con-name", profile, "ssid", ssid]
        add_result = run_command(add_cmd, timeout=12.0)
        if add_result.returncode != 0:
            return (add_result.stderr or add_result.stdout or "Failed to create temporary NetworkManager profile.").strip()

        run_command(["nmcli", "connection", "modify", profile, "connection.autoconnect", "no"], timeout=8.0)
        if bssid:
            run_command(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", bssid], timeout=8.0)

        if password:
            sec_result = run_command(
                ["nmcli", "connection", "modify", profile, "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password],
                timeout=10.0,
            )
            if sec_result.returncode != 0:
                return (sec_result.stderr or sec_result.stdout or "Failed to configure Wi-Fi password.").strip()

        up_result = run_command(["nmcli", "--wait", "30", "connection", "up", profile, "ifname", interface], timeout=35.0)
        if up_result.returncode == 0:
            return ""
        return (up_result.stderr or up_result.stdout or "Failed to activate temporary Wi-Fi profile.").strip()

    def _connect_with_wpa_supplicant(self, interface: str, ssid: str, password: str, bssid: str) -> str:
        if not tool_exists("wpa_supplicant"):
            return "wpa_supplicant not available."

        self._cleanup_wpa_runtime(interface, restore_managed=False)

        temp_path = ""
        ctrl_dir = ""
        pid_file = f"/tmp/swissknife_wpa_{interface}.pid"
        success = False
        try:
            ctrl_dir = tempfile.mkdtemp(prefix=f"swissknife_wpa_ctrl_{interface}_")
            conf_content = self._build_wpa_supplicant_config(ssid, password, bssid, ctrl_dir)
            with tempfile.NamedTemporaryFile("w", prefix=f"swissknife_{interface}_", suffix=".conf", delete=False, encoding="utf-8") as handle:
                handle.write(conf_content)
                temp_path = handle.name

            run_command(["nmcli", "device", "set", interface, "managed", "no"], timeout=8.0)
            run_command(["ip", "link", "set", interface, "up"], timeout=5.0)

            start = run_command(
                ["wpa_supplicant", "-B", "-P", pid_file, "-i", interface, "-c", temp_path],
                timeout=12.0,
            )
            if start.returncode != 0:
                return (start.stderr or start.stdout or "Failed to start wpa_supplicant.").strip()

            if not self._wait_for_wifi_association(interface, timeout=20.0):
                return "wpa_supplicant started but Wi-Fi association did not complete."

            dhcp_error = self._request_dhcp_lease(interface)
            if dhcp_error:
                return dhcp_error

            subnet = self._wait_for_ipv4(interface, timeout=20.0)
            if not subnet:
                return "Associated, but no IPv4 lease was obtained."
            success = True
            self._wpa_managed_interface = interface
            self._wpa_pid_file = pid_file
            self._wpa_ctrl_dir = ctrl_dir
            return ""
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            if not success:
                self._cleanup_wpa_runtime(interface, restore_managed=True, ctrl_dir_override=ctrl_dir, pid_file_override=pid_file)
            elif ctrl_dir != self._wpa_ctrl_dir and ctrl_dir and os.path.isdir(ctrl_dir):
                try:
                    shutil.rmtree(ctrl_dir, ignore_errors=True)
                except Exception:
                    pass

    def _build_wpa_supplicant_config(self, ssid: str, password: str, bssid: str, ctrl_dir: str) -> str:
        safe_ssid = ssid.replace("\\", "\\\\").replace('"', '\\"')
        safe_password = password.replace("\\", "\\\\").replace('"', '\\"')
        lines = [
            f"ctrl_interface={ctrl_dir}",
            "update_config=0",
            "network={",
            f'    ssid="{safe_ssid}"',
            "    scan_ssid=1",
        ]
        if password:
            lines.append(f'    psk="{safe_password}"')
        else:
            lines.append("    key_mgmt=NONE")
        if bssid:
            lines.append(f"    bssid={normalize_mac(bssid)}")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _cleanup_wpa_runtime(
        self,
        interface: str,
        restore_managed: bool,
        ctrl_dir_override: str = "",
        pid_file_override: str = "",
    ) -> None:
        if not interface:
            return

        pid_file = pid_file_override or self._wpa_pid_file
        ctrl_dir = ctrl_dir_override or self._wpa_ctrl_dir

        if pid_file and os.path.exists(pid_file):
            try:
                with open(pid_file, "r", encoding="utf-8") as handle:
                    pid_text = handle.read().strip()
                if pid_text.isdigit():
                    run_command(["kill", "-TERM", pid_text], timeout=3.0)
            except Exception:
                pass
            try:
                os.remove(pid_file)
            except OSError:
                pass

        run_command(["pkill", "-f", f"wpa_supplicant.*-i{interface}"], timeout=4.0)
        run_command(["pkill", "-f", f"wpa_supplicant.*-i {interface}"], timeout=4.0)

        sock_path = f"/run/wpa_supplicant/{interface}"
        if os.path.exists(sock_path):
            try:
                os.remove(sock_path)
            except OSError:
                pass

        if ctrl_dir and os.path.isdir(ctrl_dir):
            try:
                shutil.rmtree(ctrl_dir, ignore_errors=True)
            except Exception:
                pass

        if restore_managed:
            run_command(["nmcli", "device", "set", interface, "managed", "yes"], timeout=8.0)

        if interface == self._wpa_managed_interface:
            self._wpa_managed_interface = ""
        if pid_file == self._wpa_pid_file:
            self._wpa_pid_file = ""
        if ctrl_dir == self._wpa_ctrl_dir:
            self._wpa_ctrl_dir = ""

    def _wait_for_wifi_association(self, interface: str, timeout: float = 20.0) -> bool:
        end = time.time() + max(3.0, timeout)
        while time.time() < end and self.running:
            bssid, _ssid = self._read_iw_link(interface)
            if bssid:
                return True
            time.sleep(1.0)
        return False

    def _request_dhcp_lease(self, interface: str) -> str:
        if tool_exists("dhclient"):
            run_command(["dhclient", "-r", interface], timeout=8.0)
            result = run_command(["dhclient", interface], timeout=25.0)
            if result.returncode == 0:
                return ""
            return (result.stderr or result.stdout or "dhclient failed to acquire lease.").strip()

        if tool_exists("dhcpcd"):
            result = run_command(["dhcpcd", "-n", interface], timeout=20.0)
            if result.returncode == 0:
                return ""
            return (result.stderr or result.stdout or "dhcpcd failed to acquire lease.").strip()

        if tool_exists("udhcpc"):
            result = run_command(["udhcpc", "-i", interface, "-n", "-q", "-t", "5"], timeout=25.0)
            if result.returncode == 0:
                return ""
            return (result.stderr or result.stdout or "udhcpc failed to acquire lease.").strip()

        return "No DHCP client available (install dhclient, dhcpcd, or udhcpc)."

    def _is_bssid_visible(self, interface: str, bssid: str) -> bool:
        target = normalize_mac(bssid)
        result = run_command(
            ["nmcli", "-t", "-f", "BSSID", "device", "wifi", "list", "ifname", interface],
            timeout=8.0,
        )
        if result.returncode != 0:
            return False
        visible = {normalize_mac(line.strip()) for line in result.stdout.splitlines() if line.strip()}
        return target in visible

    def _build_visibility_hint(self, interface: str, ssid: str, bssid: str) -> str:
        result = run_command(
            ["nmcli", "-t", "--escape", "yes", "-f", "SSID,BSSID", "device", "wifi", "list", "ifname", interface],
            timeout=8.0,
        )
        if result.returncode != 0:
            return ""

        wanted_ssid = (ssid or "").strip()
        wanted_bssid = normalize_mac(bssid)
        seen_ssids: List[str] = []
        seen_bssids: List[str] = []
        ssid_match = False
        bssid_match = False
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            ssid_raw, bssid_raw = split_nmcli_escaped(line, 2)
            current_ssid = nmcli_unescape(ssid_raw).strip()
            current_bssid = normalize_mac(nmcli_unescape(bssid_raw))
            if current_ssid and current_ssid not in seen_ssids:
                seen_ssids.append(current_ssid)
            if current_bssid and current_bssid not in seen_bssids:
                seen_bssids.append(current_bssid)
            if wanted_ssid and current_ssid == wanted_ssid:
                ssid_match = True
            if wanted_bssid and current_bssid == wanted_bssid:
                bssid_match = True

        if wanted_ssid and wanted_bssid:
            if ssid_match and bssid_match:
                return "SSID/BSSID visible in nmcli list, verify password/security mode"
            if ssid_match and not bssid_match:
                return "SSID visible, chosen BSSID not currently visible"
            if not ssid_match and bssid_match:
                return "BSSID visible, SSID text mismatch (possible hidden/escaped name)"
            if seen_ssids:
                return f"nmcli cannot see chosen SSID now; visible: {', '.join(seen_ssids[:4])}"
            return "nmcli sees no nearby SSIDs on selected interface"
        return ""

    def _ensure_client_mode(self, interface: str) -> None:
        mode = self._get_interface_mode(interface).lower()
        if self._is_client_capable_mode(mode):
            return
        if mode in {"ap", "master", "monitor"}:
            raise RuntimeError(
                f"Interface '{interface}' is in {mode.upper()} mode. "
                "Select a managed client interface for ARP scan."
            )

    def _get_interface_subnet(self, interface: str) -> Optional[ipaddress.IPv4Network]:
        result = run_command(["ip", "-o", "-f", "inet", "addr", "show", "dev", interface], timeout=3.0)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if "inet" not in parts:
                    continue
                idx = parts.index("inet")
                if idx + 1 >= len(parts):
                    continue
                cidr = parts[idx + 1]
                try:
                    iface = ipaddress.ip_interface(cidr)
                except ValueError:
                    continue
                if isinstance(iface.ip, ipaddress.IPv4Address):
                    return iface.network

        route_result = run_command(["ip", "-o", "-4", "route", "show", "dev", interface], timeout=3.0)
        if route_result.returncode != 0:
            return None
        for line in route_result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "default":
                continue
            try:
                network = ipaddress.ip_network(parts[0], strict=False)
            except ValueError:
                continue
            if isinstance(network, ipaddress.IPv4Network):
                return network
        return None

    def _get_interface_ipv4(self, interface: str) -> Optional[ipaddress.IPv4Address]:
        result = run_command(["ip", "-o", "-f", "inet", "addr", "show", "dev", interface], timeout=3.0)
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            parts = line.split()
            if "inet" not in parts:
                continue
            idx = parts.index("inet")
            if idx + 1 >= len(parts):
                continue
            cidr = parts[idx + 1]
            try:
                iface = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            if isinstance(iface.ip, ipaddress.IPv4Address):
                return iface.ip
        return None

    def _wait_for_ipv4(self, interface: str, timeout: float = 15.0) -> Optional[ipaddress.IPv4Network]:
        end = time.time() + max(1.0, timeout)
        while time.time() < end and self.running:
            subnet = self._get_interface_subnet(interface)
            if subnet:
                return subnet
            time.sleep(1.0)
        return None

    def _read_iw_link(self, interface: str) -> Tuple[str, str]:
        result = run_command(["iw", "dev", interface, "link"], timeout=3.0)
        if result.returncode != 0:
            return "", ""
        if "Not connected." in result.stdout:
            return "", ""

        bssid = ""
        ssid = ""
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("Connected to "):
                bssid = line.split("Connected to ", 1)[1].split(" ", 1)[0].strip().upper()
            elif line.startswith("SSID:"):
                ssid = line.split("SSID:", 1)[1].strip()
        return bssid, ssid

    def _default_route_interface(self) -> str:
        result = run_command(["ip", "route", "show", "default"], timeout=3.0)
        if result.returncode != 0:
            return ""
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1].strip()
        return ""

    def _find_interface_for_target(self, target: WiFiNetwork, preferred: str) -> str:
        interfaces = [preferred] + [iface for iface in self._list_wifi_interfaces() if iface != preferred]
        target_bssid = normalize_mac(target.bssid)
        target_ssid = target.ssid or ""

        fallback_iface = ""
        for iface in interfaces:
            mode = (
                self._interface_profiles.get(iface).mode
                if iface in self._interface_profiles
                else self._get_interface_mode(iface)
            )
            if not self._is_client_capable_mode(mode):
                continue
            bssid, ssid = self._read_iw_link(iface)
            if not bssid and not ssid:
                continue
            if not fallback_iface:
                fallback_iface = iface
            if bssid and normalize_mac(bssid) == target_bssid:
                return iface
            if target_ssid and ssid == target_ssid:
                return iface
        return fallback_iface

    def _resolve_connected_interface_and_subnet(
        self,
        preferred_interface: str,
        target: WiFiNetwork,
        timeout: float = 25.0,
    ) -> Tuple[str, Optional[ipaddress.IPv4Network]]:
        end = time.time() + max(3.0, timeout)
        last_interface = preferred_interface

        while time.time() < end and self.running:
            linked_iface = self._find_interface_for_target(target, preferred_interface)
            if linked_iface:
                last_interface = linked_iface
                subnet = self._get_interface_subnet(linked_iface)
                if subnet:
                    return linked_iface, subnet

            default_iface = self._default_route_interface()
            if default_iface and default_iface in self._list_wifi_interfaces():
                mode = (
                    self._interface_profiles.get(default_iface).mode
                    if default_iface in self._interface_profiles
                    else self._get_interface_mode(default_iface)
                )
                if not self._is_client_capable_mode(mode):
                    default_iface = ""

            if default_iface:
                last_interface = default_iface
                subnet = self._get_interface_subnet(default_iface)
                if subnet:
                    return default_iface, subnet

            subnet = self._get_interface_subnet(preferred_interface)
            if subnet:
                return preferred_interface, subnet
            time.sleep(1.0)

        return last_interface, None

    def _prepare_network_manager(self, interface: str) -> None:
        self._cleanup_wpa_runtime(interface, restore_managed=False)
        run_command(["nmcli", "radio", "wifi", "on"], timeout=8.0)
        run_command(["nmcli", "device", "set", interface, "managed", "yes"], timeout=8.0)
        run_command(["ip", "link", "set", interface, "up"], timeout=5.0)

    def _collect_arp_entries(self, interface: str, subnet: ipaddress.IPv4Network) -> None:
        hosts = self._hosts_for_sweep(interface, subnet)
        arp_scan_error_shown = False

        for round_no in range(1, self.rounds + 1):
            if not self.running:
                break

            self.console.print(f"[dim]ARP scan round {round_no}/{self.rounds} ({len(hosts)} hosts)[/dim]")

            scan_rows, scan_error = self._run_arp_scan(interface, subnet)
            for row in scan_rows:
                self._remember_device(row)

            if scan_rows:
                time.sleep(0.4)
                continue

            if scan_error and not arp_scan_error_shown:
                self.console.print(f"[yellow]arp-scan fallback activated:[/yellow] {scan_error}")
                arp_scan_error_shown = True

            self._ping_sweep(interface, hosts, workers=64)

            entries = self._read_ip_neighbors(interface)
            for entry in entries:
                self._remember_device(entry)
            time.sleep(0.5)

    def _run_arp_scan(self, interface: str, subnet: ipaddress.IPv4Network) -> Tuple[List[ArpDevice], str]:
        commands = [
            ["arp-scan", "-I", interface, "--numeric", str(subnet)],
            ["arp-scan", "-I", interface, "--numeric", "--localnet"],
        ]
        errors: List[str] = []

        for cmd in commands:
            result = run_command(cmd, timeout=50.0)
            if result.returncode == 0:
                rows = self._parse_arp_scan_output(result.stdout)
                if rows:
                    return rows, ""
            error = (result.stderr or "").strip()
            if error:
                errors.append(error)

        return [], errors[0] if errors else ""

    def _parse_arp_scan_output(self, output: str) -> List[ArpDevice]:
        rows: List[ArpDevice] = []
        seen_ips: set[str] = set()
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = ARP_SCAN_RE.match(line)
            if not match:
                continue

            ip_addr = match.group("ip")
            mac = normalize_mac(match.group("mac"))
            if ip_addr in seen_ips:
                continue
            seen_ips.add(ip_addr)

            vendor = (match.group("vendor") or "").strip()
            if not vendor:
                vendor = self._lookup_vendor(mac)
            rows.append(
                ArpDevice(
                    ip=ip_addr,
                    mac=mac,
                    vendor=vendor or "Unknown",
                    state="REACHABLE",
                    source="arp-scan",
                )
            )
        return rows

    def _hosts_for_sweep(self, interface: str, subnet: ipaddress.IPv4Network) -> List[str]:
        all_hosts = list(subnet.hosts())
        if len(all_hosts) <= self.max_hosts:
            return [str(host) for host in all_hosts]

        local_ip = self._get_interface_ipv4(interface)
        if local_ip and local_ip in subnet:
            total = len(all_hosts)
            local_index = max(0, min(total - 1, int(local_ip) - int(subnet.network_address) - 1))
            half = self.max_hosts // 2
            start = max(0, local_index - half)
            end = min(total, start + self.max_hosts)
            start = max(0, end - self.max_hosts)
            selection = all_hosts[start:end]
            return [str(host) for host in selection]

        step = max(1, len(all_hosts) // self.max_hosts)
        sampled = all_hosts[::step][: self.max_hosts]
        return [str(host) for host in sampled]

    def _ping_sweep(self, interface: str, hosts: List[str], workers: int = 32) -> None:
        queue_lock = threading.Lock()
        index = {"value": 0}

        def next_host() -> Optional[str]:
            with queue_lock:
                pos = index["value"]
                if pos >= len(hosts):
                    return None
                index["value"] += 1
                return hosts[pos]

        def worker() -> None:
            while self.running and not self._stop_event.is_set():
                host = next_host()
                if host is None:
                    return
                run_command(
                    [
                        "ping",
                        "-c",
                        "1",
                        "-W",
                        str(max(1, int(self.ping_timeout))),
                        "-I",
                        interface,
                        host,
                    ],
                    timeout=max(2.0, self.ping_timeout + 1.2),
                )

        pool: List[threading.Thread] = []
        for _ in range(max(1, workers)):
            thread = threading.Thread(target=worker, daemon=True)
            pool.append(thread)
            thread.start()

        for thread in pool:
            thread.join()

    def _read_ip_neighbors(self, interface: str) -> List[ArpDevice]:
        result = run_command(["ip", "neigh", "show", "dev", interface], timeout=4.0)
        if result.returncode != 0:
            return []

        rows: List[ArpDevice] = []
        for raw_line in result.stdout.splitlines():
            match = IP_NEIGH_RE.match(raw_line.strip())
            if not match:
                continue
            ip_addr = match.group("ip")
            mac = normalize_mac(match.group("mac"))
            state = (match.group("state") or "").upper()
            if not MAC_RE.fullmatch(mac):
                continue
            if state in {"FAILED", "INCOMPLETE"}:
                continue
            rows.append(
                ArpDevice(
                    ip=ip_addr,
                    mac=mac,
                    vendor=self._lookup_vendor(mac),
                    state=state or "UNKNOWN",
                )
            )
        return rows

    def _lookup_vendor(self, mac: str) -> str:
        prefix = normalize_oui_key(mac)
        if not prefix:
            return "Unknown"
        return self._vendors_by_oui.get(prefix, "Unknown")

    def _remember_device(self, entry: ArpDevice) -> None:
        existing = self._devices_by_ip.get(entry.ip)
        if not existing:
            self._devices_by_ip[entry.ip] = entry
            return
        existing.mac = entry.mac
        existing.vendor = entry.vendor
        existing.state = entry.state

    def _render_summary(self, elapsed_sec: int) -> None:
        devices = sorted(
            self._devices_by_ip.values(),
            key=lambda item: tuple(int(part) for part in item.ip.split(".")),
        )

        table = Table(title="ARP Devices", box=box.SIMPLE_HEAVY)
        table.add_column("IP", style="bold")
        table.add_column("MAC", style="magenta")
        table.add_column("Vendor")
        table.add_column("State", justify="right")

        for item in devices:
            table.add_row(item.ip, item.mac, item.vendor, item.state)

        if devices:
            self.console.print(table)
        else:
            self.console.print(Panel("No ARP devices detected in this run.", border_style="yellow"))

        lines = [
            f"Target SSID: {(self._target_network.ssid if self._target_network else '-') or '<hidden>'}",
            f"Subnet: {self._connected_subnet or '-'}",
            f"Devices found: {len(devices)}",
        ]
        if self._error:
            lines.append(f"Error: {self._error}")

        self.console.print(Panel("\n".join(lines), title="Summary", border_style="green" if devices else "cyan"))

    @staticmethod
    def _freq_to_channel(freq_mhz: int) -> Optional[int]:
        if 2412 <= freq_mhz <= 2472:
            return int((freq_mhz - 2407) / 5)
        if freq_mhz == 2484:
            return 14
        if 5000 <= freq_mhz <= 5900:
            return int((freq_mhz - 5000) / 5)
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SwissKnife ARP scanner")
    parser.add_argument("--interface", default="auto", help="Wi-Fi interface to use (default: auto)")
    parser.add_argument("--scan-duration", type=int, default=0, help="Wi-Fi scan duration in seconds")
    parser.add_argument("--ssid", default="", help="Preferred SSID to join")
    parser.add_argument("--password", default="", help="Wi-Fi password (optional)")
    parser.add_argument("--rounds", type=int, default=2, help="Number of ARP collection rounds (default: 2)")
    parser.add_argument("--max-hosts", type=int, default=384, help="Max hosts per round (default: 384)")
    parser.add_argument("--ping-timeout", type=float, default=0.8, help="Ping timeout seconds (default: 0.8)")
    parser.add_argument("--oui-db", default=DEFAULT_OUI_DB, help="Path to OUI vendor database")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    module = ArpScanner(
        interface=args.interface,
        preferred_ssid=args.ssid,
        password=args.password,
        scan_duration=args.scan_duration,
        rounds=args.rounds,
        max_hosts=args.max_hosts,
        ping_timeout=args.ping_timeout,
        oui_db=args.oui_db,
    )
    module.run()


if __name__ == "__main__":
    main()
