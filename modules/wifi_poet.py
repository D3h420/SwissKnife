#!/usr/bin/env python3
"""
WiFi Poet – moduł SwissKnife
Reklamuje kolejne linijki z inwokacji Pana Tadeusza jako SSID-y
Używa mdk4 w trybie beacon flood (wymaga zainstalowanego mdk4)
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
from typing import List, Optional

# Rich fallback (jak w BluetoothPoet)
try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.group import Group
except ModuleNotFoundError:
    # bardzo uproszczony fallback
    class Console:
        def print(self, *args, **kwargs): print(*args)
    class Panel:
        def __init__(self, renderable, **_): self.renderable = renderable
        def __str__(self): return str(self.renderable)
    class Table:
        def __init__(self, **_): self.rows = []; self.columns = []
        def add_column(self, name, **_): self.columns.append(name)
        def add_row(self, *vals): self.rows.append(vals)
        def __str__(self): return "\n".join([" | ".join(self.columns)] + [" | ".join(map(str,r)) for r in self.rows])
    class Group:
        def __init__(self, *objs): self.objs = objs
        def __str__(self): return "\n\n".join(map(str, self.objs))
    class Live:
        def __init__(self, renderable, **_): self.renderable = renderable; self.console = Console()
        def __enter__(self): self.console.print(self.renderable); return self
        def update(self, r, **_): self.renderable = r; self.console.print(r)
        def __exit__(self, *_): pass

try:
    from core.module import Module
except ImportError:
    class Module:
        def __init__(self, name="Module"):
            self.name = name
            self.console = Console()
            self.status = "idle"
            self.running = False
        def stop(self):
            self.running = False
            self.status = "stopped"

PAN_TADEUSZ_INWOKACJA = """
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
""".strip().splitlines()

@dataclass
class FakeAP:
    ssid: str
    bssid: str
    channel: int
    status: str = "ACTIVE"

class WiFiPoet(Module):
    def __init__(
        self,
        interface: str = "wlan0mon",
        count: int = 24,
        duration: int = 0,
        refresh: float = 1.0,
        seed: Optional[int] = None,
        channel: int = 6,
        beacon_interval_ms: int = 100,
    ):
        super().__init__(name="WiFi Poet")
        self.interface = interface
        self.count = max(8, min(40, int(count)))          # sensowny zakres
        self.duration = max(0, int(duration))
        self.refresh = max(0.3, float(refresh))
        self.seed = seed
        self.channel = int(channel)
        self.beacon_interval_ms = int(beacon_interval_ms)
        self.running = False
        self._stop_event = threading.Event()
        self._proc: Optional[subprocess.Popen] = None
        self._fake_aps: List[FakeAP] = []
        self._error = None

        lines = [line.strip() for line in PAN_TADEUSZ_INWOKACJA if line.strip()]
        rng = random.Random(seed)
        selected = [rng.choice(lines) for _ in range(self.count)] if seed else lines[:self.count]

        for i, ssid in enumerate(selected):
            bssid = f"02:{random.randbytes(5).hex(':')}"   # local admin bit
            self._fake_aps.append(FakeAP(ssid=ssid, bssid=bssid, channel=self.channel))

    def run(self):
        if os.geteuid() != 0:
            self.console.print("[red]WiFi Poet wymaga uprawnień root[/red]")
            return

        self.running = True
        self.status = "running"
        self._stop_event.clear()

        self.console.print(Panel.fit(
            "WiFi Poet (tryb laboratoryjny)\n"
            "Flood beaconów z wierszem Mickiewicza\n"
            "Używaj TYLKO w kontrolowanym środowisku!",
            border_style="cyan",
            title="SwissKnife"
        ))

        try:
            self._start_mdk4_flood()
            self.console.print("[bold cyan]Flood beaconów w toku – Ctrl+C aby zatrzymać[/bold cyan]")

            with Live(
                self._build_view(0),
                console=self.console,
                refresh_per_second=int(1 / self.refresh) + 1,
            ) as live:
                start = time.time()
                while not self._stop_event.is_set():
                    elapsed = int(time.time() - start)
                    if self.duration > 0 and elapsed >= self.duration:
                        break
                    live.update(self._build_view(elapsed))
                    time.sleep(self.refresh)

            self.status = "completed"

        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]Przerwano przez użytkownika[/yellow]")
        except Exception as e:
            self._error = str(e)
            self.status = "error"
            self.console.print(f"[red]Błąd: {e}[/red]")
        finally:
            self.running = False
            self._stop()
            elapsed = int(time.time() - start)
            self._render_summary(elapsed)

    def _start_mdk4_flood(self):
        # Przygotowujemy plik z listą SSID-ów
        ssid_list_file = "/tmp/wifipoet_ssids.txt"
        with open(ssid_list_file, "w") as f:
            for ap in self._fake_aps:
                f.write(f"{ap.ssid}\n")

        cmd = [
            "mdk4", self.interface, "b",
            "-c", str(self.channel),
            "-f", ssid_list_file,
            "-s", str(self.beacon_interval_ms),
            "-m",                      # spoofowane MAC-e (z listy lub losowe)
        ]

        self.console.print(f"[yellow]Uruchamiam: {' '.join(cmd)}[/yellow]")

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )

    def _stop(self):
        if self._proc:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=3)
            except:
                pass
            self._proc = None

    def _build_view(self, elapsed: int) -> Group:
        table = Table(title="Reklamowane sieci WiFi")
        table.add_column("SSID", style="bold cyan")
        table.add_column("BSSID", style="magenta")
        table.add_column("Channel")
        table.add_column("Status")

        for ap in self._fake_aps:
            table.add_row(ap.ssid, ap.bssid, str(ap.channel), ap.status)

        header = Panel(
            f"Aktywne: {len(self._fake_aps)}\n"
            f"Czas: {elapsed}s\n"
            f"Kanał: {self.channel}\n"
            f"Interfejs: {self.interface}",
            title="WiFi Poet Status",
            border_style="cyan"
        )
        return Group(header, table)

    def _render_summary(self, elapsed: int):
        samples = [ap.ssid for ap in self._fake_aps[:6]]
        lines = [
            f"Status: {self.status}",
            f"Czas działania: {elapsed}s",
            f"Przygotowano sieci: {len(self._fake_aps)}",
            "Przykładowe SSID:",
            *[f"  • {s}" for s in samples],
        ]
        if self._error:
            lines.append(f"Błąd: {self._error}")
        self.console.print(Panel("\n".join(lines), title="Podsumowanie WiFi Poet", border_style="green"))

def main():
    parser = argparse.ArgumentParser(description="SwissKnife WiFi Poet – beacon flood z Mickiewiczem")
    parser.add_argument("--interface", default="wlan0mon", help="Interfejs w trybie monitor (np. wlan0mon)")
    parser.add_argument("--count", type=int, default=24, help="Ile różnych SSID-ów")
    parser.add_argument("--duration", type=int, default=0, help="Czas trwania (0 = aż do Ctrl+C)")
    parser.add_argument("--refresh", type=float, default=1.0, help="Odświeżanie widoku")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--channel", type=int, default=6, help="Kanał WiFi")
    parser.add_argument("--beacon-ms", type=int, default=100, help="Interwał beaconów w ms")

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