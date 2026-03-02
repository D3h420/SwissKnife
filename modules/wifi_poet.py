#!/usr/bin/env python3
"""
WiFi Poet module for SwissKnife - test edition.
Broadcast 10 poem lines on all 2.4 GHz channels.
"""
from __future__ import annotations
import argparse
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

# Rich import with fallback
try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    RICH_AVAILABLE = True
except ModuleNotFoundError:
    RICH_AVAILABLE = False

# Fallback classes (simplified)
class Console:
    def print(self, *args, **kwargs): print(*args if args else '')

class Panel:
    def __init__(self, renderable, **kwargs): self.renderable = renderable
    def __str__(self): return str(self.renderable) if self.renderable else ''

class Table:
    def __init__(self, **kwargs):
        self.rows = []
        self.columns = []
    def add_column(self, name, **kwargs):
        self.columns.append(name)
    def add_row(self, *vals):
        self.rows.append(vals)
    def __str__(self):
        if not self.rows: return ''
        headers = self.columns or [f"Col{i+1}" for i in range(len(self.rows[0]))]
        widths = [max(len(str(row[i])) for row in [headers] + list(self.rows)) for i in range(len(headers))]
        s = ' | '.join(h.ljust(w) for h, w in zip(headers, widths)) + '\n'
        s += '-+-'.join('-' * w for w in widths) + '\n'
        for row in self.rows:
            s += ' | '.join(str(v).ljust(w) for v, w in zip(row, widths)) + '\n'
        return s

class Group:
    def __init__(self, *objs): self.objs = objs
    def __str__(self): return "\n".join(str(o) for o in self.objs)

class Live:
    def __init__(self, renderable, **kwargs): self.renderable = renderable
    def __enter__(self): print('\033c' + str(self.renderable)); return self
    def update(self, renderable, **kwargs): print('\033c' + str(renderable))
    def __exit__(self, *args): pass

class Prompt:
    @staticmethod
    def ask(prompt, default=None, **kwargs):
        sys.stdout.write(prompt + (f" [{default}]" if default else "") + ": ")
        sys.stdout.flush()
        return sys.stdin.readline().strip() or default or ''

try:
    from core.module import Module
except ImportError:
    class Module:
        def __init__(self, name="Module"):
            self.name = name
            self.console = Console()
            self.status = "idle"
            self.running = False
        def stop(self): self.running = False; self.status = "stopped"
        def execute(self): pass

# Short test version: 10 lines + 1 test line
POEM_LINES = [
    "Lithuania, my homeland! You are like health;",
    "Only one who lost you can truly value you,",
    "Today I see your beauty in full adornment,",
    "I describe it because I long for you.",
    "Holy Virgin, guardian of bright Czestochowa,",
    "And light above Ostra Gate and castle walls,",
    "You protect Nowogrodek and its faithful people,",
    "You restored me to health when I was a child,",
    "When from my weeping mother into Your care,",
    "I was entrusted and raised from darkened eyes;",
    "[TEST] WiFi Poet - broadcast on all channels"
]

DISCLAIMER = "WARNING: LAB ONLY - private use only!"

@dataclass
class FakeAP:
    ssid: str
    bssid: str
    channel: int
    status: str = "ON AIR"

class WiFiPoet(Module):
    def __init__(self):
        super().__init__(name="WiFi Poet Test")
        self.interface = "auto"
        self.original_interface = None
        self.count = 11                      # 10 + 1 test line
        self.duration = 0
        self.refresh = 1.2
        self.seed = None
        self.channels = list(range(1, 14))   # 1-13 (2.4 GHz)
        self.channel_hop_sec = 12.0          # channel change every ~12 seconds
        self.beacon_rate = 100               # increased frequency
        self.power_level = 30
        self.max_rows = 11

        self.running = False
        self.status = "idle"
        self._stop_event = threading.Event()
        self._signal_handlers: Dict[int, Any] = {}
        self._error: Optional[str] = None
        self._fake_aps: List[FakeAP] = []
        self._proc: Optional[subprocess.Popen] = None
        self._ssid_list_file: Optional[str] = None
        self._current_channel = self.channels[0]
        self._last_hop_ts = 0.0
        self._original_mode: str = "unknown"
        self._monitor_enabled = False
        self._packets_sent = 0
        self.console = Console()

    def configure(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.count = max(5, min(30, int(self.count)))
        self.channels = [ch for ch in self.channels if 1 <= ch <= 13] or [1]
        self.beacon_rate = max(30, min(300, int(self.beacon_rate)))
        self._current_channel = self.channels[0]
        self._build_fake_aps()
        return self

    def execute(self) -> None:
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()

        if os.geteuid() != 0:
            self.console.print("[red]Root privileges are required[/red]")
            self._restore_signal_handlers()
            return

        if not self._tool_exists("mdk4"):
            self.console.print("[red]mdk4 not found - install with: sudo apt install mdk4[/red]")
            self._restore_signal_handlers()
            return

        chosen = self._select_interface()
        if not chosen:
            self.console.print("[red]No interface selected[/red]")
            self._restore_signal_handlers()
            return

        current_mode = self._get_interface_mode(chosen).lower()
        if current_mode == "monitor":
            self.console.print(f"[green]{chosen} is already in monitor mode[/green]")
            self.interface = chosen
            self.original_interface = chosen
            self._monitor_enabled = True
            self._using_airmon = False
        else:
            self.original_interface = chosen
            self.console.print(f"[yellow]Enabling monitor mode on {chosen}...[/yellow]")
            monitor_iface = self._enable_monitor_mode(chosen)
            if not monitor_iface:
                self.console.print(f"[red]Failed to enable monitor mode on {chosen}[/red]")
                self._restore_signal_handlers()
                return
            self.interface = monitor_iface
            self._monitor_enabled = True
            self.console.print(f"[green]Monitor interface active: {self.interface}[/green]")

        self.console.print(Panel(
            "WiFi Poet TEST - 11 SSIDs on all 2.4 GHz channels",
            border_style="red",
            title="WARNING",
            expand=False
        ))
        self.console.print("[bold red]ON-AIR BROADCAST - check Wi-Fi list on your phone![/bold red]")
        self.console.print(f"[dim]{DISCLAIMER}[/dim]")

        try:
            if not self._start_engine():
                raise RuntimeError("Failed to start mdk4")
            self.console.print("[bold green]BROADCAST STARTED - 100 beacons/s[/bold green]")
            self.console.print("[bold cyan]Ctrl+C to stop[/bold cyan]")

            with Live(
                self._build_view(0),
                console=self.console,
                refresh_per_second=2,
                screen=False
            ) as live:
                last_emit = 0.0
                while not self._stop_event.is_set():
                    elapsed = int(time.time() - started)
                    if self.duration > 0 and elapsed >= self.duration:
                        break
                    self._tick_channel_rotation()
                    live.update(self._build_view(elapsed))
                    now = time.time()
                    if now - last_emit >= 1.0:
                        last_emit = now
                    self._sleep_interruptible(self.refresh)
            self.status = "completed"
        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]Stopping...[/yellow]")
        except Exception as exc:
            self.status = "error"
            self._error = str(exc)
            self.console.print(f"[red]Error: {exc}[/red]")
        finally:
            self.running = False
            self._stop_event.set()
            self._stop_engine()
            self._disable_monitor_mode()
            elapsed = max(0, int(time.time() - started))
            self._render_summary(elapsed)
            self._restore_signal_handlers()

    # Remaining methods (logic unchanged, shorter rendering)

    def _enable_monitor_mode(self, iface: str) -> Optional[str]:
        if self._get_interface_mode(iface).lower() == "monitor":
            return iface
        try:
            subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            result = subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                output = result.stdout + result.stderr
                for pattern in [r"monitor mode enabled on (\w+)", r"enabled on (\w+mon)"]:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        self._using_airmon = True
                        return match.group(1)
                time.sleep(2)
                for i in self._discover_wifi_interfaces():
                    if i.endswith("mon") and i != iface:
                        self._using_airmon = True
                        return i
        except:
            pass

        # Manual fallback method
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], check=False)
            time.sleep(0.5)
            subprocess.run(["iw", iface, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            time.sleep(0.3)
            if subprocess.run(["iw", iface, "set", "type", "monitor"], capture_output=True, check=False).returncode == 0:
                subprocess.run(["ip", "link", "set", iface, "up"], check=False)
                time.sleep(1)
                if self._get_interface_mode(iface).lower() == "monitor":
                    self._using_airmon = False
                    return iface
        except:
            pass
        return None

    def _disable_monitor_mode(self) -> None:
        if not self._monitor_enabled or not self.original_interface:
            return
        if self._using_airmon and self.interface != self.original_interface:
            subprocess.run(["airmon-ng", "stop", self.interface], capture_output=True, check=False)
            subprocess.run(["ip", "link", "set", self.original_interface, "up"], check=False)
        else:
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=False)
            time.sleep(0.5)
            target = "managed"
            subprocess.run(["iw", self.interface, "set", "type", target], check=False)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=False)
        subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        self._monitor_enabled = False

    def _start_engine(self) -> bool:
        self._ssid_list_file = f"/tmp/wifi_poet_{os.getpid()}.txt"
        try:
            with open(self._ssid_list_file, "w", encoding="utf-8") as f:
                for ap in self._fake_aps:
                    f.write(f"{ap.bssid} {ap.ssid}\n")
        except Exception as e:
            self.console.print(f"[red]Failed to write SSID list: {e}[/red]")
            return False

        if self.power_level > 0:
            try:
                subprocess.run(["iw", "dev", self.interface, "set", "txpower", "fixed", str(self.power_level * 100)], check=True)
            except:
                pass

        cmd = [
            "mdk4", self.interface, "b",
            "-c", str(self._current_channel),
            "-v", self._ssid_list_file,
            "-s", str(self.beacon_rate),
            "-m"
        ]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          stdin=subprocess.DEVNULL, preexec_fn=os.setsid, text=True, bufsize=1)
            time.sleep(2)
            if self._proc.poll() is not None:
                return False
            self._start_monitor_thread()
            return True
        except:
            return False

    def _start_monitor_thread(self):
        def monitor():
            if not self._proc or not self._proc.stderr: return
            for line in self._proc.stderr:
                if self._stop_event.is_set(): break
                line = line.strip()
                if "Packets sent" in line:
                    try:
                        self._packets_sent = int(re.search(r'Packets sent: (\d+)', line).group(1))
                    except:
                        pass
        threading.Thread(target=monitor, daemon=True).start()

    def _stop_engine(self):
        if self._proc:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=3)
            except:
                pass
            self._proc = None
        if self._ssid_list_file and os.path.exists(self._ssid_list_file):
            os.remove(self._ssid_list_file)

    def _build_view(self, elapsed: int):
        status = [
            f"ON AIR - channel {self._current_channel} | {self.beacon_rate} pps",
            f"Elapsed: {elapsed}s | Sent ~{self._packets_sent} packets",
            "Refresh Wi-Fi list on your phone"
        ]
        header = Panel("\n".join(status), title="WiFi Poet Test", border_style="red", expand=False)

        table = Table()
        table.add_column("#")
        table.add_column("SSID")
        table.add_column("BSSID")
        table.add_column("CH")
        for i, ap in enumerate(self._fake_aps, 1):
            table.add_row(str(i), ap.ssid[:48], ap.bssid, str(ap.channel))

        return Group(header, table)

    def _build_fake_aps(self):
        rng = random.Random(self.seed if self.seed else int(time.time()))
        self._fake_aps = []
        for idx, ssid in enumerate(POEM_LINES[:self.count]):
            mac = self._generate_mac(rng, idx)
            self._fake_aps.append(FakeAP(ssid=ssid, bssid=mac, channel=self._current_channel))

    def _generate_mac(self, rng: random.Random, offset: int) -> str:
        oui = [[0x02,0x11,0x22], [0x02,0x14,0xBF], [0x02,0x18,0xF8], [0x02,0x1E,0x52]][offset % 4]
        octets = oui + [rng.randint(0,255) for _ in range(3)]
        return ":".join(f"{b:02X}" for b in octets)

    def _discover_wifi_interfaces(self) -> List[str]:
        interfaces = []
        try:
            out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                if "Interface" in line:
                    iface = line.split("Interface", 1)[1].strip()
                    if iface: interfaces.append(iface)
        except:
            pass
        return interfaces

    def _get_interface_mode(self, iface: str) -> str:
        try:
            out = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                if line.startswith("type "):
                    return line.split("type", 1)[1].strip()
        except:
            pass
        return "unknown"

    def _get_interface_chipset(self, iface: str) -> str:
        try:
            result = subprocess.run(
                ["ethtool", "-i", iface],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return "unknown"

        if result.returncode != 0:
            return "unknown"

        driver = None
        bus_info = None
        for line in result.stdout.splitlines():
            if line.startswith("driver:"):
                driver = line.split(":", 1)[1].strip()
            elif line.startswith("bus-info:"):
                bus_info = line.split(":", 1)[1].strip()

        if driver and bus_info:
            return f"{driver} ({bus_info})"
        if driver:
            return driver
        return "unknown"

    def _select_interface(self) -> str:
        interfaces = self._discover_wifi_interfaces()
        if not interfaces:
            return ""
        self.console.print("")
        self.console.print("[bold]Available interfaces:[/bold]")
        for i, iface in enumerate(interfaces, 1):
            mode = self._get_interface_mode(iface)
            chipset = self._get_interface_chipset(iface)
            self.console.print(f"  {i}) {iface} - {chipset} [{mode}]")
        while True:
            choice = Prompt.ask("\nSelect interface (number or name)", default="1")
            if choice.isdigit() and 0 < int(choice) <= len(interfaces):
                return interfaces[int(choice) - 1]
            if choice in interfaces:
                return choice
            self.console.print("[yellow]Invalid selection. Try again.[/yellow]")

    def _tool_exists(self, tool: str) -> bool:
        return subprocess.run(["which", tool], capture_output=True, check=False).returncode == 0

    def _sleep_interruptible(self, seconds: float):
        deadline = time.time() + seconds
        while not self._stop_event.is_set() and time.time() < deadline:
            time.sleep(0.1)

    def _tick_channel_rotation(self):
        now = time.time()
        if now - self._last_hop_ts < self.channel_hop_sec:
            return
        self._last_hop_ts = now
        idx = self.channels.index(self._current_channel)
        self._current_channel = self.channels[(idx + 1) % len(self.channels)]
        for ap in self._fake_aps:
            ap.channel = self._current_channel
        self.console.print(f"[cyan]-> channel {self._current_channel}[/cyan]")
        if self._proc:
            self._stop_engine()
            time.sleep(0.8)
        self._start_engine()

    def _render_summary(self, elapsed: int):
        lines = [
            f"Status: {self.status}",
            f"Time: {elapsed}s",
            f"Channels tested: ~{len(self.channels)}",
            f"Packets: ~{self._packets_sent}",
            "\nLast SSIDs:",
        ]
        for i, ap in enumerate(self._fake_aps[:3], 1):
            lines.append(f"  {i}. {ap.ssid}")
        lines.append(f"\n{DISCLAIMER}")
        self.console.print(Panel("\n".join(lines), title="Summary", expand=False))

    def stop(self):
        self.running = False
        self.status = "stopped"
        self._stop_event.set()
        self._stop_engine()

    def _install_signal_handlers(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._signal_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handle_signal)
            except:
                pass

    def _restore_signal_handlers(self):
        for sig, prev in self._signal_handlers.items():
            try:
                signal.signal(sig, prev)
            except:
                pass

    def _handle_signal(self, signum, frame):
        self.stop()

def main():
    parser = argparse.ArgumentParser(description="WiFi Poet TEST - 10 lines on all channels")
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--beacon-rate", type=int, default=100)
    parser.add_argument("--channel-hop", type=float, default=12.0)
    args = parser.parse_args()

    mod = WiFiPoet()
    mod.configure(
        interface=args.interface,
        beacon_rate=args.beacon_rate,
        channel_hop_sec=args.channel_hop
    )
    try:
        mod.execute()
    except KeyboardInterrupt:
        mod.stop()
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}")
        mod.stop()

if __name__ == "__main__":
    main()
