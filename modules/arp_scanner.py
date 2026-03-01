#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

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
        rounds: int = 2,
        max_hosts: int = 384,
        ping_timeout: float = 0.8,
        oui_db: str = DEFAULT_OUI_DB,
    ) -> None:
        super().__init__(name="ARP scanner")
        self.interface = (interface or "auto").strip()
        self.preferred_ssid = preferred_ssid.strip()
        self.password = password
        self.rounds = max(1, int(rounds))
        self.max_hosts = max(32, int(max_hosts))
        self.ping_timeout = max(0.1, float(ping_timeout))
        self.oui_db = oui_db

        self.status = "idle"
        self.running = False
        self._stop_event = threading.Event()
        self._signal_handlers: Dict[int, object] = {}
        self._selected_interface: str = ""
        self._target_network: Optional[WiFiNetwork] = None
        self._connected_subnet: str = ""
        self._devices_by_ip: Dict[str, ArpDevice] = {}
        self._vendors_by_oui: Dict[str, str] = {}
        self._error: Optional[str] = None

    def run(self) -> None:
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()

        self.console.print(Panel.fit("ARP scanner", border_style="cyan", subtitle="SwissKnife"))

        try:
            self._ensure_runtime_requirements()
            self._vendors_by_oui = load_oui_database(self.oui_db)

            interface = self._select_interface()
            self._selected_interface = interface

            networks = self._scan_wifi_networks(interface)
            if not networks:
                raise RuntimeError("No Wi-Fi networks detected on selected interface.")

            self._render_networks_table(networks)
            target = self._choose_target_network(networks)
            self._target_network = target

            password = self._resolve_password_for_network(target)
            self._connect_to_network(interface, target, password)

            subnet = self._get_interface_subnet(interface)
            if not subnet:
                raise RuntimeError(
                    "Connected, but no IPv4 subnet detected. Check DHCP or static IP settings."
                )
            self._connected_subnet = str(subnet)

            self.console.print(
                "[bold cyan]Skanowanie tabeli ARP w toku... (Ctrl+C aby zatrzymac)[/bold cyan]\n"
                f"[dim]Interfejs:[/dim] {interface}  "
                f"[dim]Siec:[/dim] {target.ssid or '<hidden>'}  "
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
            self._render_summary(elapsed)
            self._emit_webui_result(elapsed)
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
        required = ["iw", "ip", "nmcli", "ping"]
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

    def _select_interface(self) -> str:
        interfaces = self._list_wifi_interfaces()
        if not interfaces:
            raise RuntimeError("No Wi-Fi interfaces found.")

        if self.interface and self.interface != "auto":
            if self.interface not in interfaces:
                raise RuntimeError(f"Interface '{self.interface}' is not available.")
            return self.interface

        if len(interfaces) == 1:
            self.console.print(f"[green]Selected interface:[/green] {interfaces[0]}")
            return interfaces[0]

        table = Table(title="Available Wi-Fi Interfaces", box=box.SIMPLE_HEAVY)
        table.add_column("#", justify="right", style="cyan", no_wrap=True)
        table.add_column("Interface", style="bold")
        for idx, iface in enumerate(interfaces, start=1):
            table.add_row(str(idx), iface)
        self.console.print(table)

        while self.running:
            raw = Prompt.ask("Select interface number", default="1", console=self.console)
            try:
                picked = int(raw)
            except ValueError:
                self.console.print("[yellow]Enter a numeric interface index.[/yellow]")
                continue
            if 1 <= picked <= len(interfaces):
                return interfaces[picked - 1]
            self.console.print("[yellow]Invalid index.[/yellow]")

        raise KeyboardInterrupt

    def _scan_wifi_networks(self, interface: str) -> List[WiFiNetwork]:
        self.console.print(f"[cyan]Scanning nearby Wi-Fi on {interface}...[/cyan]")
        result = run_command(["iw", "dev", interface, "scan"], timeout=25.0)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            raise RuntimeError(stderr or "Wi-Fi scan failed.")

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
            existing = rows.get(bssid)
            if not existing:
                rows[bssid] = entry
                return
            old_signal = existing.signal if existing.signal is not None else -999
            new_signal = entry.signal if entry.signal is not None else -999
            if new_signal > old_signal:
                rows[bssid] = entry

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
        return ordered

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
            password=True,
            console=self.console,
        )

    def _connect_to_network(self, interface: str, network: WiFiNetwork, password: str) -> None:
        self.console.print(f"[cyan]Connecting {interface} to {network.ssid or network.bssid}...[/cyan]")

        ssid_target = network.ssid if network.ssid and network.ssid != "<hidden>" else ""
        attempts: List[List[str]] = []

        if ssid_target:
            cmd = ["nmcli", "--wait", "30", "device", "wifi", "connect", ssid_target, "ifname", interface]
            if password:
                cmd += ["password", password]
            cmd += ["bssid", network.bssid]
            attempts.append(cmd)

        cmd_bssid = ["nmcli", "--wait", "30", "device", "wifi", "connect", network.bssid, "ifname", interface]
        if password:
            cmd_bssid += ["password", password]
        attempts.append(cmd_bssid)

        last_error = ""
        for cmd in attempts:
            result = run_command(cmd, timeout=35.0)
            if result.returncode == 0:
                self.console.print("[green]Wi-Fi connected.[/green]")
                return
            last_error = (result.stderr or result.stdout or "").strip()

        raise RuntimeError(last_error or "Failed to connect to selected Wi-Fi network.")

    def _get_interface_subnet(self, interface: str) -> Optional[ipaddress.IPv4Network]:
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
                return iface.network
        return None

    def _collect_arp_entries(self, interface: str, subnet: ipaddress.IPv4Network) -> None:
        hosts = [str(host) for host in subnet.hosts()]
        if len(hosts) > self.max_hosts:
            hosts = hosts[: self.max_hosts]

        for round_no in range(1, self.rounds + 1):
            if not self.running:
                break

            self.console.print(f"[dim]ARP scan round {round_no}/{self.rounds} ({len(hosts)} hosts)[/dim]")
            if tool_exists("nmap"):
                run_command(["nmap", "-sn", "-n", str(subnet)], timeout=35.0)
            else:
                self._ping_sweep(interface, hosts, workers=64)

            entries = self._read_ip_neighbors(interface)
            for entry in entries:
                self._remember_device(entry)
            time.sleep(0.5)

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
            f"Status: {self.status}",
            f"Elapsed: {elapsed_sec}s",
            f"Interface: {self._selected_interface or '-'}",
            f"Target SSID: {(self._target_network.ssid if self._target_network else '-') or '<hidden>'}",
            f"Subnet: {self._connected_subnet or '-'}",
            f"Devices found: {len(devices)}",
        ]
        if self._error:
            lines.append(f"Error: {self._error}")

        self.console.print(Panel("\n".join(lines), title="Summary", border_style="green" if devices else "cyan"))

    def _emit_webui_result(self, elapsed_sec: int) -> None:
        if os.environ.get("SWISSKNIFE_WEBUI_TASK") != "1":
            return
        payload = {
            "kind": "arp_scan",
            "running": False,
            "timestamp": int(time.time()),
            "status": self.status,
            "interface": self._selected_interface,
            "target_ssid": self._target_network.ssid if self._target_network else "",
            "subnet": self._connected_subnet,
            "duration": int(elapsed_sec),
            "device_count": len(self._devices_by_ip),
            "devices": [
                {
                    "ip": item.ip,
                    "mac": item.mac,
                    "vendor": item.vendor,
                    "state": item.state,
                    "source": item.source,
                }
                for item in sorted(
                    self._devices_by_ip.values(),
                    key=lambda row: tuple(int(part) for part in row.ip.split(".")),
                )
            ],
            "error": self._error,
        }
        print(f"[webui-result] {json.dumps(payload, ensure_ascii=False)}", flush=True)

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
        rounds=args.rounds,
        max_hosts=args.max_hosts,
        ping_timeout=args.ping_timeout,
        oui_db=args.oui_db,
    )
    module.run()


if __name__ == "__main__":
    main()
