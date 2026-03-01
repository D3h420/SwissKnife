#!/usr/bin/env python3
"""
WiFi Poet module for SwissKnife.
Educational/lab demonstration of poem-based Wi-Fi beacon lists.
Supports real beacon transmission via mdk4 when --no-simulate is used.
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
from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
except ModuleNotFoundError:
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
    class Panel:
        def __init__(self, renderable, **_):
            self.renderable = renderable
        @classmethod
        def fit(cls, renderable, **kwargs):
            return cls(renderable, **kwargs)
        def __str__(self) -> str:
            return str(self.renderable)
    class Table:
        def __init__(self, title: str = "", **_):
            self.title = title
            self.rows: List[List[str]] = []
            self.columns: List[str] = []
        def add_column(self, name, **_):
            self.columns.append(str(name))
        def add_row(self, *vals):
            self.rows.append([str(v) for v in vals])
        def __str__(self) -> str:
            parts: List[str] = [self.title] if self.title else []
            if self.columns:
                parts.append(" | ".join(self.columns))
            for row in self.rows:
                parts.append(" | ".join(row))
            return "\n".join(parts)
    class Group:
        def __init__(self, *objs):
            self.objs = objs
        def __str__(self) -> str:
            return "\n\n".join(map(str, self.objs))
    class Live:
        def __init__(self, renderable, console=None, **_):
            self.renderable = renderable
            self.console = console or Console()
        def __enter__(self):
            self.console.print(self.renderable)
            return self
        def update(self, renderable, **_):
            self.renderable = renderable
            self.console.print(renderable)
        def __exit__(self, *_):
            return False
    class Prompt:
        @staticmethod
        def ask(prompt: str, default: str = "", password: bool = False, console: Optional[Console] = None) -> str:
            sys.stdout.write(prompt)
            if default:
                sys.stdout.write(f" [{default}]")
            sys.stdout.write(": ")
            sys.stdout.flush()
            raw = sys.stdin.readline()
            value = (raw or "").strip()
            return value or default

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

LAB_DISCLAIMER = "Laboratory beacon demonstration only. No connection possible. Private lab use."

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
        refresh: float = 0.6,
        seed: Optional[int] = None,
        channel: int = 6,
        channels: Optional[List[int]] = None,
        channel_hop_sec: float = 12.0,
        simulate: bool = True,
        max_rows: int = 12,
    ) -> None:
        super().__init__(name="WiFi Poet")
        self.interface = (interface or "auto").strip()
        self.count = max(8, min(40, int(count)))
        self.duration = max(0, int(duration))
        self.refresh = max(0.2, float(refresh))
        self.seed = seed
        self.channel = max(1, min(14, int(channel)))
        self.channels = [ch for ch in (channels or [1, 6, 11]) if 1 <= ch <= 14] or [self.channel]
        self.channel_hop_sec = max(5.0, float(channel_hop_sec))
        self.simulate = bool(simulate)
        self.max_rows = max(5, int(max_rows))
        self.running = False
        self.status = "idle"
        self._stop_event = threading.Event()
        self._signal_handlers: Dict[int, object] = {}
        self._error: Optional[str] = None
        self._fake_aps: List[FakeAP] = []
        self._proc: Optional[subprocess.Popen] = None
        self._ssid_list_file: Optional[str] = None
        self._current_channel = self.channels[0]
        self._last_hop_ts = 0.0
        self._build_fake_aps()

    def run(self) -> None:
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()

        if os.geteuid() != 0:
            self.status = "error"
            self._error = "WiFi Poet requires root privileges."
            self.console.print(f"[red]{self._error}[/red]")
            self._render_summary(0)
            self._restore_signal_handlers()
            return

        self.interface = self._select_interface()
        if not self.interface:
            self.status = "error"
            self._error = "No usable Wi-Fi interface found."
            self.console.print(f"[red]{self._error}[/red]")
            self._render_summary(0)
            self._restore_signal_handlers()
            return

        self.console.print(
            Panel.fit(
                "WiFi Poet (lab mode)\n"
                "Poem-based SSID beacon list demonstration.",
                border_style="cyan",
                title="SwissKnife",
            )
        )
        self.console.print("[bold yellow]Heads up: I'm about to wake the Poet...[/bold yellow]")
        self.console.print(f"[dim]{LAB_DISCLAIMER}[/dim]")

        try:
            self._start_engine()
            self.console.print("[bold cyan]WiFi Poet is running. Press Ctrl+C to stop.[/bold cyan]")
            with Live(
                self._build_view(0),
                console=self.console,
                refresh_per_second=max(2, int(1.0 / self.refresh) + 1),
            ) as live:
                last_emit = 0.0
                while not self._stop_event.is_set():
                    elapsed = int(time.time() - started)
                    if self.duration > 0 and elapsed >= self.duration:
                        break
                    self._tick_channel_rotation()
                    live.update(self._build_view(elapsed), refresh=True)
                    now = time.time()
                    if now - last_emit >= 1.0:
                        self._emit_webui_result(running=True, elapsed_sec=elapsed)
                        last_emit = now
                    self._sleep_interruptible(self.refresh)
            if self.status != "stopped":
                self.status = "completed"
        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]WiFi Poet interrupted by user.[/yellow]")
        except Exception as exc:
            self.status = "error"
            self._error = str(exc)
            self.console.print(f"[red]WiFi Poet error:[/red] {exc}")
        finally:
            self.running = False
            self._stop_event.set()
            self._stop_engine()
            self._mark_stopped()
            elapsed = max(0, int(time.time() - started))
            self._render_summary(elapsed)
            self._emit_webui_result(running=False, elapsed_sec=elapsed)
            self._restore_signal_handlers()

    def stop(self) -> None:
        self.running = False
        self.status = "stopped"
        self._stop_event.set()
        self._stop_engine()

    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._signal_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handle_signal)
            except Exception:
                continue

    def _restore_signal_handlers(self) -> None:
        for sig, previous in self._signal_handlers.items():
            try:
                signal.signal(sig, previous)
            except Exception:
                continue

    def _handle_signal(self, _signum: int, _frame: object) -> None:
        self.stop()

    def _build_fake_aps(self) -> None:
        lines = [line.strip() for line in PAN_TADEUSZ_INVOKATION.splitlines() if line.strip()]
        rng = random.Random(self.seed)
        picked: List[str] = []
        for idx in range(self.count):
            if self.seed is None:
                picked.append(lines[idx % len(lines)])
            else:
                picked.append(rng.choice(lines))
        self._fake_aps = [
            FakeAP(ssid=ssid, bssid=self._generate_local_admin_mac(rng), channel=self._current_channel)
            for ssid in picked
        ]

    def _generate_local_admin_mac(self, rng: random.Random) -> str:
        octets = [rng.randint(0, 255) for _ in range(6)]
        octets[0] = (octets[0] | 0x02) & 0xFE
        return ":".join(f"{value:02X}" for value in octets)

    def _select_interface(self) -> str:
        # ... (pozostawiam bez zmian – Twój kod wyboru interfejsu jest bardzo dobry)
        # (wklejam go tutaj tylko po to, by całość była kompletna – możesz zostawić swoją wersję)
        interfaces = self._discover_wifi_interfaces()
        if not interfaces:
            return ""
        if len(interfaces) == 1:
            return interfaces[0]
        table = Table(title="Available Wi-Fi Interfaces")
        table.add_column("#", justify="right")
        table.add_column("Interface", style="bold cyan")
        for idx, iface in enumerate(interfaces, start=1):
            table.add_row(str(idx), iface)
        self.console.print(table)
        while True:
            raw = Prompt.ask("Select interface number", default="1", console=self.console).strip()
            if raw.isdigit():
                picked = int(raw)
                if 1 <= picked <= len(interfaces):
                    return interfaces[picked - 1]
            if raw in interfaces:
                return raw
            self.console.print("[yellow]Invalid selection. Try again.[/yellow]")

    def _start_engine(self) -> None:
        self._last_hop_ts = time.time()
        if self.simulate:
            self.console.print("[yellow][SIMULATED MODE] No real RF transmission.[/yellow]")
            return

        # REAL MODE – uruchamiamy mdk4
        if not self._tool_exists("mdk4"):
            raise RuntimeError("mdk4 not found. Install it to use real mode.")

        self._ssid_list_file = f"/tmp/wifi_poet_ssids_{os.getpid()}.txt"
        with open(self._ssid_list_file, "w", encoding="utf-8") as f:
            for ap in self._fake_aps:
                f.write(f"{ap.ssid}\n")

        cmd = [
            "mdk4", self.interface, "b",
            "-c", str(self._current_channel),
            "-f", self._ssid_list_file,
            "-s", "100",  # interwał beaconów w ms – możesz dodać flagę jeśli chcesz
            "-m",         # spoof MAC
        ]

        self.console.print(f"[dim]Launching real beacon flood: {' '.join(cmd)}[/dim]")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                text=True,
            )
            # Sprawdzamy czy wystartował
            time.sleep(1.5)
            if self._proc.poll() is not None:
                err = self._proc.stderr.read() if self._proc.stderr else ""
                raise RuntimeError(f"mdk4 failed to start: {err.strip()}")
        except Exception as e:
            raise RuntimeError(f"Failed to start mdk4: {e}")

    def _stop_engine(self) -> None:
        if self._proc:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=4)
            except:
                pass
            self._proc = None
        if self._ssid_list_file and os.path.exists(self._ssid_list_file):
            try:
                os.remove(self._ssid_list_file)
            except:
                pass
            self._ssid_list_file = None

    def _tick_channel_rotation(self) -> None:
        now = time.time()
        if now - self._last_hop_ts < self.channel_hop_sec:
            return
        self._last_hop_ts = now
        current_idx = self.channels.index(self._current_channel) if self._current_channel in self.channels else 0
        next_idx = (current_idx + 1) % len(self.channels)
        self._current_channel = self.channels[next_idx]
        for ap in self._fake_aps:
            ap.channel = self._current_channel
        # W trybie realnym – restart mdk4 z nowym kanałem (proste, ale działa)
        if not self.simulate and self._proc:
            self._stop_engine()
            time.sleep(0.4)
            self._start_engine()

    # Pozostałe metody bez zmian (lub minimalne poprawki)

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

    def _build_view(self, elapsed: int):
        table = Table(title="Poem SSID Showcase")
        table.add_column("SSID", style="bold cyan")
        table.add_column("BSSID", style="magenta")
        table.add_column("CH", justify="right")
        table.add_column("Status")
        visible = self._fake_aps[: self.max_rows]
        for ap in visible:
            table.add_row(ap.ssid, ap.bssid, str(ap.channel), ap.status)
        if len(self._fake_aps) > self.max_rows:
            table.add_row(
                f"... +{len(self._fake_aps) - self.max_rows} more entries",
                "-",
                "-",
                "-",
            )
        header = Panel(
            "\n".join(
                [
                    f"Mode: {'SIMULATED' if self.simulate else 'REAL'}",
                    f"Entries: {len(self._fake_aps)}",
                    f"Elapsed: {elapsed}s",
                    f"Interface: {self.interface}",
                    f"Current channel: {self._current_channel}",
                    f"Hop interval: {int(self.channel_hop_sec)}s",
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
            f"Mode: {'SIMULATED' if self.simulate else 'REAL'}",
            "Sample SSIDs:",
            *[f"- {name}" for name in samples],
            f"Notice: {LAB_DISCLAIMER}",
        ]
        if self._error:
            lines.append(f"Error: {self._error}")
        self.console.print(Panel("\n".join(lines), title="WiFi Poet Summary", border_style="green"))

    def _emit_webui_result(self, *, running: bool, elapsed_sec: int) -> None:
        if os.environ.get("SWISSKNIFE_WEBUI_TASK") != "1":
            return
        payload = {
            "kind": "wifi_poet",
            "running": bool(running),
            "timestamp": int(time.time()),
            "status": self.status,
            "interface": self.interface,
            "duration": int(elapsed_sec),
            "simulate": self.simulate,
            "disclaimer": LAB_DISCLAIMER,
            "channel": self._current_channel,
            "channels": self.channels,
            "device_count": len(self._fake_aps),
            "devices": [
                {
                    "ssid": ap.ssid,
                    "bssid": ap.bssid,
                    "channel": ap.channel,
                    "status": ap.status,
                }
                for ap in self._fake_aps
            ],
            "error": self._error,
        }
        print(f"[webui-result] {json.dumps(payload, ensure_ascii=False)}", flush=True)

    def _tool_exists(self, tool: str) -> bool:
        return subprocess.run(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0

def parse_channels(raw: str) -> List[int]:
    if not raw:
        return [1, 6, 11]
    channels: List[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            ch = int(token)
        except ValueError:
            continue
        if 1 <= ch <= 14 and ch not in channels:
            channels.append(ch)
    return channels or [1, 6, 11]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SwissKnife WiFi Poet (lab demonstration)")
    parser.add_argument("--interface", default="auto", help="Wi-Fi interface (default: auto)")
    parser.add_argument("--count", type=int, default=24, help="Number of poem SSIDs")
    parser.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0 = until Ctrl+C)")
    parser.add_argument("--refresh", type=float, default=0.6, help="Live view refresh in seconds")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for deterministic output")
    parser.add_argument("--channel", type=int, default=6, help="Default Wi-Fi channel")
    parser.add_argument("--channels", default="1,6,11", help="Rotation channel list, e.g. 1,6,11")
    parser.add_argument("--channel-hop", type=float, default=12.0, help="Channel hop interval in seconds")
    parser.add_argument("--max-rows", type=int, default=12, help="Max rows shown in live table")
    parser.add_argument("--simulate", dest="simulate", action="store_true", default=True, help="Simulation mode (default)")
    parser.add_argument("--no-simulate", dest="simulate", action="store_false", help="Disable simulation – use real mdk4")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    module = WiFiPoet(
        interface=args.interface,
        count=args.count,
        duration=args.duration,
        refresh=args.refresh,
        seed=args.seed,
        channel=args.channel,
        channels=parse_channels(args.channels),
        channel_hop_sec=args.channel_hop,
        simulate=args.simulate,
        max_rows=args.max_rows,
    )
    module.run()

if __name__ == "__main__":
    main()