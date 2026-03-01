#!/usr/bin/env python3
"""
WiFi Poet module for SwissKnife.
Broadcasts poem lines as SSIDs via mdk4 beacon flood mode.
"""

from __future__ import annotations

import argparse
import os
import random
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:
    class Console:  # type: ignore[override]
        def print(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            del kwargs
            print(*args)

    class Panel:  # type: ignore[override]
        def __init__(self, renderable, **_):  # type: ignore[no-untyped-def]
            self.renderable = renderable

        @classmethod
        def fit(cls, renderable, **kwargs):  # type: ignore[no-untyped-def]
            return cls(renderable, **kwargs)

        def __str__(self) -> str:
            return str(self.renderable)

    class Table:  # type: ignore[override]
        def __init__(self, title: str = "", **_):  # type: ignore[no-untyped-def]
            self.title = title
            self.rows: List[List[str]] = []
            self.columns: List[str] = []

        def add_column(self, name, **_):  # type: ignore[no-untyped-def]
            self.columns.append(str(name))

        def add_row(self, *vals):  # type: ignore[no-untyped-def]
            self.rows.append([str(v) for v in vals])

        def __str__(self) -> str:
            parts: List[str] = [self.title] if self.title else []
            if self.columns:
                parts.append(" | ".join(self.columns))
            for row in self.rows:
                parts.append(" | ".join(row))
            return "\n".join(parts)

    class Group:  # type: ignore[override]
        def __init__(self, *objs):  # type: ignore[no-untyped-def]
            self.objs = objs

        def __str__(self) -> str:
            return "\n\n".join(map(str, self.objs))

    class Live:  # type: ignore[override]
        def __init__(self, renderable, console=None, **_):  # type: ignore[no-untyped-def]
            self.renderable = renderable
            self.console = console or Console()

        def __enter__(self):  # type: ignore[no-untyped-def]
            self.console.print(self.renderable)
            return self

        def update(self, renderable, **_):  # type: ignore[no-untyped-def]
            self.renderable = renderable
            self.console.print(renderable)

        def __exit__(self, *_):  # type: ignore[no-untyped-def]
            return False

try:
    from core.module import Module  # type: ignore
except ImportError:
    class Module:
        def __init__(self, name: str = "Module"):
            self.name = name
            self.console = Console()
            self.status = "idle"
            self.running = False

        def stop(self) -> None:
            self.running = False
            self.status = "stopped"


PAN_TADEUSZ_INVOKATION = """
Litwo! Ojczyzno moja! ty jesteś jak zdrowie;
Ile cię trzeba cenić, ten tylko się dowie,
Kto cię stracił. Dziś piękność twą w całej ozdobie
Widzę i opisuję, bo tęsknię po tobie.
Panno Święta, co Jasnej bronisz Częstochowy
I w Ostrej świecisz Bramie! Ty, co gród zamkowy
Nowogródzki ochraniasz z jego wiernym ludem!
Jak mnie dziecko do zdrowia powróciłaś cudem
Gdy od płaczącej matki pod Twoją opiekę
Ofiarowany, martwą podniosłem powiekę;
I zaraz mogłem pieszo do Twych świątyń progu
Iść za wrócone życie podziękować Bogu:
Tak nas powrócisz cudem na Ojczyzny łono.
Tymczasem przenoś moją duszę utęsknioną
Do tych pagórków leśnych, do tych łąk zielonych,
Szeroko nad błękitnym Niemnem rozciągnionych;
Do tych pól malowanych zbożem rozmaitem,
Wyzłacanych pszenicą, posrebrzanych żytem;
Gdzie bursztynowy świerzop, gryka jak śnieg biała,
Gdzie panieńskim rumieńcem dzięcielina pała,
A wszystko przepasane, jakby wstęgą, miedzą
Zieloną, na niej z rzadka ciche grusze siedzą.
""".strip()


@dataclass
class FakeAP:
    ssid: str
    bssid: str
    channel: int
    status: str = "ACTIVE"


class WiFiPoet(Module):
    def __init__(
        self,
        interface: str = "auto",
        count: int = 24,
        duration: int = 0,
        refresh: float = 1.0,
        seed: Optional[int] = None,
        channel: int = 6,
        beacon_interval_ms: int = 100,
    ) -> None:
        super().__init__(name="WiFi Poet")
        self.interface = (interface or "auto").strip()
        self.count = max(8, min(40, int(count)))
        self.duration = max(0, int(duration))
        self.refresh = max(0.3, float(refresh))
        self.seed = seed
        self.channel = max(1, min(14, int(channel)))
        self.beacon_interval_ms = max(10, int(beacon_interval_ms))
        self.running = False
        self.status = "idle"

        self._stop_event = threading.Event()
        self._proc: Optional[subprocess.Popen] = None
        self._error: Optional[str] = None
        self._ssid_list_file: Optional[str] = None
        self._fake_aps: List[FakeAP] = []

        self._build_fake_aps()

    def stop(self) -> None:
        self.running = False
        self.status = "stopped"
        self._stop_event.set()
        self._stop_process()

    def run(self) -> None:
        start = time.time()
        if os.geteuid() != 0:
            self.console.print("[red]WiFi Poet requires root privileges.[/red]")
            return
        if not self._tool_exists("mdk4"):
            self.console.print("[red]Required tool not found: mdk4[/red]")
            return

        self.interface = self._resolve_interface()
        if not self.interface:
            self.console.print("[red]No usable Wi-Fi interface found.[/red]")
            return

        self.running = True
        self.status = "running"
        self._stop_event.clear()

        self.console.print(
            Panel.fit(
                "WiFi Poet (lab mode)\n"
                "Beacon flood with poem-based SSIDs.\n"
                "Use only in a controlled environment.",
                border_style="cyan",
                title="SwissKnife",
            )
        )
        self.console.print("[bold yellow]Heads up: I'm about to wake the Poet...[/bold yellow]")

        try:
            self._start_mdk4_flood()
            self.console.print("[bold cyan]WiFi Poet is broadcasting now. Press Ctrl+C to stop.[/bold cyan]")

            with Live(
                self._build_view(0),
                console=self.console,
                refresh_per_second=max(2, int(1.0 / self.refresh) + 1),
            ) as live:
                while not self._stop_event.is_set():
                    elapsed = int(time.time() - start)
                    if self.duration > 0 and elapsed >= self.duration:
                        break
                    live.update(self._build_view(elapsed), refresh=True)
                    self._sleep_interruptible(self.refresh)

            if self.status != "stopped":
                self.status = "completed"

        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]WiFi Poet interrupted by user.[/yellow]")
        except Exception as exc:
            self._error = str(exc)
            self.status = "error"
            self.console.print(f"[red]WiFi Poet error:[/red] {exc}")
        finally:
            self.running = False
            self._stop_event.set()
            self._mark_stopped()
            self._stop_process()
            self._cleanup_ssid_file()
            elapsed = int(time.time() - start)
            self._render_summary(elapsed)

    def _tool_exists(self, tool: str) -> bool:
        return (
            subprocess.run(
                ["which", tool],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )

    def _build_fake_aps(self) -> None:
        lines = [line.strip() for line in PAN_TADEUSZ_INVOKATION.splitlines() if line.strip()]
        rng = random.Random(self.seed)
        selected = []
        for idx in range(self.count):
            if self.seed is None:
                selected.append(lines[idx % len(lines)])
            else:
                selected.append(rng.choice(lines))
        for ssid in selected:
            self._fake_aps.append(
                FakeAP(ssid=ssid, bssid=self._generate_local_admin_mac(rng), channel=self.channel)
            )

    def _generate_local_admin_mac(self, rng: random.Random) -> str:
        octets = [rng.randint(0, 255) for _ in range(6)]
        octets[0] = (octets[0] | 0x02) & 0xFE
        return ":".join(f"{value:02X}" for value in octets)

    def _discover_wifi_interfaces(self) -> List[str]:
        result = subprocess.run(
            ["iw", "dev"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        interfaces: List[str] = []
        if result.returncode == 0:
            for raw in result.stdout.splitlines():
                line = raw.strip()
                if line.startswith("Interface "):
                    name = line.split("Interface", 1)[1].strip()
                    if name and name not in interfaces:
                        interfaces.append(name)
        return interfaces

    def _get_interface_mode(self, iface: str) -> str:
        result = subprocess.run(
            ["iw", "dev", iface, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return "unknown"
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if line.startswith("type "):
                return line.split("type", 1)[1].strip()
        return "unknown"

    def _is_interface_up(self, iface: str) -> bool:
        result = subprocess.run(
            ["ip", "link", "show", "dev", iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        return result.returncode == 0 and "UP" in result.stdout

    def _resolve_interface(self) -> str:
        interfaces = self._discover_wifi_interfaces()
        if not interfaces:
            return ""

        if not sys.stdin.isatty():
            if self.interface and self.interface not in ("", "auto"):
                return self.interface
            return interfaces[0]

        table = Table(title="Available Wi-Fi interfaces")
        table.add_column("#", justify="right")
        table.add_column("Interface", style="bold cyan")
        table.add_column("Mode")
        table.add_column("State")

        for idx, iface in enumerate(interfaces, start=1):
            mode = self._get_interface_mode(iface)
            state = "UP" if self._is_interface_up(iface) else "DOWN"
            table.add_row(str(idx), iface, mode, state)

        self.console.print("")
        self.console.print(table)

        default_iface = self.interface if self.interface not in ("", "auto") else interfaces[0]
        prompt = f"Select interface (number/name, default: {default_iface}): "

        while True:
            raw = input(prompt).strip()
            if not raw:
                return default_iface
            if raw.isdigit():
                index = int(raw)
                if 1 <= index <= len(interfaces):
                    return interfaces[index - 1]
            if raw in interfaces:
                return raw
            self.console.print("[yellow]Invalid interface selection. Try again.[/yellow]")

    def _start_mdk4_flood(self) -> None:
        self._ssid_list_file = f"/tmp/wifi_poet_ssids_{os.getpid()}.txt"
        with open(self._ssid_list_file, "w", encoding="utf-8") as handle:
            for ap in self._fake_aps:
                handle.write(f"{ap.ssid}\n")

        cmd = [
            "mdk4",
            self.interface,
            "b",
            "-c",
            str(self.channel),
            "-f",
            self._ssid_list_file,
            "-s",
            str(self.beacon_interval_ms),
            "-m",
        ]

        self.console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )

    def _stop_process(self) -> None:
        if not self._proc:
            return
        try:
            os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            self._proc.wait(timeout=3)
        except Exception:
            pass
        finally:
            self._proc = None

    def _cleanup_ssid_file(self) -> None:
        if self._ssid_list_file and os.path.exists(self._ssid_list_file):
            try:
                os.remove(self._ssid_list_file)
            except OSError:
                pass
        self._ssid_list_file = None

    def _sleep_interruptible(self, seconds: float) -> None:
        deadline = time.time() + max(0.0, seconds)
        while not self._stop_event.is_set():
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            time.sleep(min(0.2, remaining))

    def _mark_stopped(self) -> None:
        for ap in self._fake_aps:
            ap.status = "STOPPED"

    def _build_view(self, elapsed: int) -> Group:
        table = Table(title="Broadcasted Wi-Fi SSIDs")
        table.add_column("SSID", style="bold cyan")
        table.add_column("BSSID", style="magenta")
        table.add_column("Channel", justify="right")
        table.add_column("Status")

        for ap in self._fake_aps:
            table.add_row(ap.ssid, ap.bssid, str(ap.channel), ap.status)

        header = Panel(
            "\n".join(
                [
                    f"Active entries: {sum(1 for ap in self._fake_aps if ap.status == 'ACTIVE')}",
                    f"Total entries: {len(self._fake_aps)}",
                    f"Elapsed: {elapsed}s",
                    f"Channel: {self.channel}",
                    f"Interface: {self.interface}",
                ]
            ),
            title="WiFi Poet Status",
            border_style="cyan",
        )
        return Group(header, table)

    def _render_summary(self, elapsed: int) -> None:
        samples = [ap.ssid for ap in self._fake_aps[:6]]
        lines = [
            f"Status: {self.status}",
            f"Runtime: {elapsed}s",
            f"Prepared SSIDs: {len(self._fake_aps)}",
            "Sample SSIDs:",
            *[f"- {name}" for name in samples],
        ]
        if self._error:
            lines.append(f"Error: {self._error}")
        self.console.print(Panel("\n".join(lines), title="WiFi Poet Summary", border_style="green"))


def main() -> None:
    parser = argparse.ArgumentParser(description="SwissKnife WiFi Poet beacon flood")
    parser.add_argument("--interface", default="auto", help="Wi-Fi interface (default: auto)")
    parser.add_argument("--count", type=int, default=24, help="Number of poem SSIDs")
    parser.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0 = until Ctrl+C)")
    parser.add_argument("--refresh", type=float, default=1.0, help="Live view refresh in seconds")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for deterministic output")
    parser.add_argument("--channel", type=int, default=6, help="Wi-Fi channel")
    parser.add_argument("--beacon-ms", type=int, default=100, help="Beacon interval in ms")

    args = parser.parse_args()
    poet = WiFiPoet(
        interface=args.interface,
        count=args.count,
        duration=args.duration,
        refresh=args.refresh,
        seed=args.seed,
        channel=args.channel,
        beacon_interval_ms=args.beacon_ms,
    )
    poet.run()


if __name__ == "__main__":
    main()
