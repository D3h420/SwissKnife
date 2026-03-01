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
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Any

# Próba importu rich z fallbackiem
try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ModuleNotFoundError:
    RICH_AVAILABLE = False
    # Klasy zastępcze
    class Console:
        def print(self, *args, **kwargs):
            print(*args if args else '')
        def log(self, *args, **kwargs):
            print(*args if args else '')
    
    class Panel:
        def __init__(self, renderable, **kwargs):
            self.renderable = renderable
        @classmethod
        def fit(cls, renderable, **kwargs):
            return cls(renderable, **kwargs)
        def __str__(self):
            return str(self.renderable) if self.renderable else ''
    
    class Table:
        def __init__(self, **kwargs):
            self.title = kwargs.get('title', '')
            self.rows = []
            self.columns = []
        def add_column(self, name, **kwargs):
            self.columns.append(str(name))
        def add_row(self, *vals):
            self.rows.append([str(v) for v in vals])
        def __str__(self):
            parts = [self.title] if self.title else []
            if self.columns:
                parts.append(" | ".join(self.columns))
            for row in self.rows:
                parts.append(" | ".join(row))
            return "\n".join(parts)
    
    class Group:
        def __init__(self, *objs):
            self.objs = objs
        def __str__(self):
            return "\n\n".join(str(o) for o in self.objs)
    
    class Live:
        def __init__(self, renderable, **kwargs):
            self.renderable = renderable
        def __enter__(self):
            print(self.renderable)
            return self
        def update(self, renderable, **kwargs):
            print(renderable)
        def __exit__(self, *args):
            pass
    
    class Prompt:
        @staticmethod
        def ask(prompt, default=None, **kwargs):
            sys.stdout.write(prompt + (" [{}]".format(default) if default else "") + ": ")
            sys.stdout.flush()
            return sys.stdin.readline().strip() or default or ''

# Import modułu bazowego SwissKnife
try:
    from core.module import Module  # type: ignore
    SWISSKNIFE_MODULE = True
except ImportError:
    SWISSKNIFE_MODULE = False
    # Klasa zastępcza
    class Module:
        def __init__(self, name: str = "Module"):
            self.name = name
            self.console = Console()
            self.status = "idle"
            self.running = False
        def stop(self) -> None:
            self.running = False
            self.status = "stopped"
        def execute(self) -> None:
            """Metoda wywoływana przez SwissKnife"""
            pass

# Rozszerzony poemat - cała Inwokacja podzielona na linie
PAN_TADEUSZ_LINES = [
    "Litwo! Ojczyzno moja! ty jesteś jak zdrowie;",
    "Ile cię trzeba cenić, ten tylko się dowie,",
    "Kto cię stracił. Dziś piękność twą w całej ozdobie",
    "Widzę i opisuję, bo tęsknię po tobie.",
    "Panno Święta, co Jasnej bronisz Częstochowy",
    "I w Ostrej świecisz Bramie! Ty, co gród zamkowy",
    "Nowogródzki ochraniasz z jego wiernym ludem!",
    "Jak mnie dziecko do zdrowia powróciłaś cudem",
    "Gdy od płaczącej matki pod Twoją opiekę",
    "Ofiarowany, martwą podniosłem powiekę;",
    "I zaraz mogłem pieszo do Twych świątyń progu",
    "Iść za wrócone życie podziękować Bogu:",
    "Tak nas powrócisz cudem na Ojczyzny łono.",
    "Tymczasem przenoś moją duszę utęsknioną",
    "Do tych pagórków leśnych, do tych łąk zielonych,",
    "Szeroko nad błękitnym Niemnem rozciągnionych;",
    "Do tych pól malowanych zbożem rozmaitem,",
    "Wyzłacanych pszenicą, posrebrzanych żytem;",
    "Gdzie bursztynowy świerzop, gryka jak śnieg biała,",
    "Gdzie panieńskim rumieńcem dzięcielina pała,",
    "A wszystko przepasane, jakby wstęgą, miedzą",
    "Zieloną, na niej z rzadka ciche grusze siedzą.",
]

# Dodatkowe linie dla większej liczby SSID
EXTRA_LINES = [
    "Śród takich pól przed laty, nad błękitnym Niemnem",
    "Rosły, ach! rosły piękne dziecięce lata moje!",
    "I ojciec mój, w komorze, wesoły i szczęśliwy",
    "O przyszłości mej dumał, o przyszłości niwy.",
    "I matka, w wieńcu z jarzyn, w ogrodzie robiła",
    "I mnie, dziecinę, uczyła pacierza i szyła.",
]

LAB_DISCLAIMER = "⚠️ Laboratorium: Tylko demonstracja beaconów. Żadna sieć nie umożliwia połączenia."

@dataclass
class FakeAP:
    ssid: str
    bssid: str
    channel: int
    power: int = 0
    status: str = "📡 ACTIVE"

class WiFiPoet(Module):
    """Główna klasa modułu WiFi Poet"""
    
    def __init__(self):
        """Inicjalizacja z domyślnymi parametrami"""
        super().__init__(name="WiFi Poet")
        
        # Domyślne parametry
        self.interface = "auto"
        self.count = 24
        self.duration = 0
        self.refresh = 0.6
        self.seed = None
        self.channel = 6
        self.channels = [1, 6, 11]
        self.channel_hop_sec = 15.0
        self.simulate = True
        self.max_rows = 12
        self.beacon_rate = 50
        self.power_level = 30
        
        # Stan wewnętrzny
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
        self._detected_by_scanner = False
        
        self.console = Console()

    def configure(self, **kwargs):
        """Konfiguruje moduł z podanymi parametrami"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        # Walidacja parametrów
        self.count = max(8, min(50, int(self.count)))
        self.refresh = max(0.2, float(self.refresh))
        self.channel = max(1, min(14, int(self.channel)))
        self.channels = [ch for ch in self.channels if 1 <= ch <= 14] or [self.channel]
        self.channel_hop_sec = max(3.0, float(self.channel_hop_sec))
        self.max_rows = max(5, int(self.max_rows))
        self.beacon_rate = max(20, min(1000, int(self.beacon_rate)))
        self.power_level = max(0, min(100, int(self.power_level)))
        
        # Ustaw bieżący kanał
        self._current_channel = self.channels[0]
        
        # Zbuduj listę AP
        self._build_fake_aps()
        
        return self

    def execute(self) -> None:
        """Główna metoda wywoływana przez SwissKnife (zamiast run)"""
        self._run()

    def _run(self) -> None:
        """Wewnętrzna implementacja głównej pętli"""
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()

        # Sprawdź uprawnienia root
        if os.geteuid() != 0:
            self.status = "error"
            self._error = "WiFi Poet wymaga uprawnień root."
            self.console.print(f"[red]{self._error}[/red]")
            self._render_summary(0)
            self._restore_signal_handlers()
            return

        # Wybierz interfejs
        self.interface = self._select_interface()
        if not self.interface:
            self.status = "error"
            self._error = "Nie znaleziono interfejsu Wi-Fi."
            self.console.print(f"[red]{self._error}[/red]")
            self._render_summary(0)
            self._restore_signal_handlers()
            return

        # Zapisz oryginalny tryb
        self._original_mode = self._get_interface_mode(self.interface)
        
        # W trybie rzeczywistym przełącz na monitor
        if not self.simulate:
            if not self._ensure_monitor_mode(self.interface):
                self.status = "error"
                self._error = f"Nie udało się włączyć trybu monitor na {self.interface}."
                self.console.print(f"[red]{self._error}[/red]")
                self._render_summary(0)
                self._restore_signal_handlers()
                return

        # Wyświetl nagłówek
        self.console.print(
            Panel.fit(
                "WiFi Poet (tryb lab)\n"
                "Demonstracja beaconów z fragmentami Pana Tadeusza.",
                border_style="cyan",
                title="SwissKnife",
            )
        )
        
        if self.simulate:
            self.console.print("[yellow][SYMULACJA] Brak emisji w eterze.[/yellow]")
        else:
            self.console.print("[bold yellow]🔴 UWAGA: RZECZYWISTA EMISJA BEACONÓW![/bold yellow]")
        
        self.console.print(f"[dim]{LAB_DISCLAIMER}[/dim]")

        try:
            # Uruchom silnik
            self._start_engine()
            
            if not self.simulate:
                self.console.print("[bold green]✓ Emisja aktywna! Sprawdź listę Wi-Fi w telefonie![/bold green]")
            
            self.console.print("[bold cyan]Naciśnij Ctrl+C aby zatrzymać.[/bold cyan]")
            
            # Główna pętla z Live view
            with Live(
                self._build_view(0),
                console=self.console,
                refresh_per_second=max(2, int(1.0 / self.refresh) + 1),
                screen=False
            ) as live:
                last_emit = 0.0
                while not self._stop_event.is_set():
                    elapsed = int(time.time() - started)
                    
                    # Sprawdź czas trwania
                    if self.duration > 0 and elapsed >= self.duration:
                        break
                    
                    # Rotacja kanałów
                    self._tick_channel_rotation()
                    
                    # Aktualizuj widok
                    live.update(self._build_view(elapsed))
                    
                    # Emituj do WebUI
                    now = time.time()
                    if now - last_emit >= 1.0:
                        self._emit_webui_result(running=True, elapsed_sec=elapsed)
                        last_emit = now
                    
                    # Czekaj z możliwością przerwania
                    self._sleep_interruptible(self.refresh)
            
            if self.status != "stopped":
                self.status = "completed"
                
        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]WiFi Poet zatrzymany przez użytkownika.[/yellow]")
        except Exception as exc:
            self.status = "error"
            self._error = str(exc)
            self.console.print(f"[red]Błąd WiFi Poet:[/red] {exc}")
        finally:
            # Sprzątanie
            self.running = False
            self._stop_event.set()
            self._stop_engine()
            self._restore_interface_mode()
            self._mark_stopped()
            elapsed = max(0, int(time.time() - started))
            self._render_summary(elapsed)
            self._emit_webui_result(running=False, elapsed_sec=elapsed)
            self._restore_signal_handlers()

    def stop(self) -> None:
        """Zatrzymuje moduł"""
        self.running = False
        self.status = "stopped"
        self._stop_event.set()
        self._stop_engine()

    def _install_signal_handlers(self) -> None:
        """Instaluje obsługę sygnałów"""
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._signal_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handle_signal)
            except Exception:
                continue

    def _restore_signal_handlers(self) -> None:
        """Przywraca oryginalne obsługi sygnałów"""
        for sig, previous in self._signal_handlers.items():
            try:
                signal.signal(sig, previous)
            except Exception:
                continue

    def _handle_signal(self, _signum: int, _frame: Any) -> None:
        """Obsługa sygnałów"""
        self.stop()

    def _build_fake_aps(self) -> None:
        """Buduje listę AP z zachowaniem kolejności"""
        all_lines = PAN_TADEUSZ_LINES + EXTRA_LINES
        
        if self.seed is not None:
            rng = random.Random(self.seed)
            selected = rng.sample(all_lines, min(self.count, len(all_lines)))
        else:
            selected = []
            for i in range(self.count):
                line = all_lines[i % len(all_lines)]
                if i >= len(PAN_TADEUSZ_LINES):
                    line = f"[{i+1}] {line}"
                selected.append(line)
        
        rng_mac = random.Random(self.seed if self.seed else random.randint(0, 999999))
        self._fake_aps = []
        
        for idx, ssid in enumerate(selected):
            mac = self._generate_local_admin_mac(rng_mac, idx)
            power = rng_mac.randint(-67, -30) if self.seed else random.randint(-67, -30)
            self._fake_aps.append(
                FakeAP(
                    ssid=ssid,
                    bssid=mac,
                    channel=self._current_channel,
                    power=power,
                    status="📡 ACTIVE"
                )
            )

    def _generate_local_admin_mac(self, rng: random.Random, seed_offset: int = 0) -> str:
        """Generuje lokalny adres MAC"""
        oui_list = [
            [0x00, 0x11, 0x22],  # Cisco
            [0x00, 0x14, 0xBF],  # Cisco
            [0x00, 0x18, 0xF8],  # Apple
            [0x00, 0x1E, 0x52],  # Samsung
            [0x00, 0x23, 0x76],  # Intel
            [0x00, 0x26, 0x5E],  # TP-Link
        ]
        
        oui = oui_list[seed_offset % len(oui_list)].copy()
        oui[0] = (oui[0] | 0x02) & 0xFE  # local admin, unicast
        
        octets = oui + [rng.randint(0, 255) for _ in range(3)]
        return ":".join(f"{b:02X}" for b in octets)

    def _discover_wifi_interfaces(self) -> List[str]:
        """Wykrywa interfejsy WiFi"""
        interfaces: List[str] = []
        
        # Metoda 1: iw dev
        try:
            result = subprocess.run(
                ["iw", "dev"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Interface" in line:
                        iface = line.split("Interface", 1)[1].strip()
                        if iface and iface not in interfaces:
                            interfaces.append(iface)
        except FileNotFoundError:
            pass
        
        # Metoda 2: ip link
        if not interfaces:
            try:
                result = subprocess.run(
                    ["ip", "-o", "link", "show"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if "wlan" in line or "wl" in line:
                            iface = line.split(": ")[1].split(":")[0]
                            if iface not in interfaces:
                                interfaces.append(iface)
            except FileNotFoundError:
                pass
        
        return interfaces

    def _get_interface_mode(self, iface: str) -> str:
        """Sprawdza tryb interfejsu"""
        try:
            result = subprocess.run(
                ["iw", "dev", iface, "info"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("type "):
                        return line.split("type", 1)[1].strip()
        except:
            pass
        return "unknown"

    def _is_interface_up(self, iface: str) -> bool:
        """Sprawdza czy interfejs jest włączony"""
        try:
            result = subprocess.run(
                ["ip", "link", "show", "dev", iface],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
            return result.returncode == 0 and "UP" in result.stdout
        except:
            return False

    def _ensure_monitor_mode(self, iface: str) -> bool:
        """Przełącza interfejs w tryb monitor"""
        current_mode = self._get_interface_mode(iface).lower()
        
        if current_mode == "monitor":
            self._monitor_enabled = True
            self.console.print(f"[green]✓ Interfejs {iface} już w trybie monitor[/green]")
            return True
        
        self.console.print(f"[yellow]Przełączanie {iface} w tryb monitor...[/yellow]")
        
        # Próba z airmon-ng
        try:
            result = subprocess.run(
                ["airmon-ng", "start", iface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "monitor mode enabled" in line.lower():
                        self._monitor_enabled = True
                        self.console.print(f"[green]✓ Tryb monitor włączony[/green]")
                        return True
        except:
            pass
        
        # Ręczne przełączanie
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], check=False)
            time.sleep(0.5)
            
            result = subprocess.run(
                ["iw", iface, "set", "type", "monitor"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            
            if result.returncode != 0:
                self.console.print(f"[red]Błąd ustawiania trybu monitor: {result.stderr}[/red]")
                subprocess.run(["ip", "link", "set", iface, "up"], check=False)
                return False
            
            subprocess.run(["ip", "link", "set", iface, "up"], check=False)
            time.sleep(1)
            
            new_mode = self._get_interface_mode(iface).lower()
            if new_mode == "monitor":
                self._monitor_enabled = True
                self.console.print(f"[green]✓ Tryb monitor włączony ręcznie[/green]")
                return True
        except Exception as e:
            self.console.print(f"[red]Błąd: {e}[/red]")
        
        return False

    def _restore_interface_mode(self) -> None:
        """Przywraca oryginalny tryb interfejsu"""
        if not self.interface or not self._monitor_enabled or self.simulate:
            return
        
        self.console.print("[yellow]Przywracanie interfejsu...[/yellow]")
        
        try:
            subprocess.run(["airmon-ng", "stop", self.interface], check=False)
        except:
            pass
        
        try:
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=False)
            time.sleep(0.5)
            
            target = self._original_mode if self._original_mode != "unknown" else "managed"
            subprocess.run(["iw", self.interface, "set", "type", target], check=False)
            
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=False)
        except:
            pass
        
        self._monitor_enabled = False
        self.console.print("[green]✓ Interfejs przywrócony[/green]")

    def _select_interface(self) -> str:
        """Wyświetla menu wyboru interfejsu"""
        interfaces = self._discover_wifi_interfaces()
        
        if not interfaces:
            return ""
        
        if self.interface and self.interface != "auto":
            if self.interface in interfaces:
                return self.interface
            return ""
        
        if len(interfaces) == 1:
            return interfaces[0]
        
        # Wyświetl tabelę interfejsów
        table = Table(title="Dostępne interfejsy WiFi")
        table.add_column("#", justify="right")
        table.add_column("Interfejs", style="bold cyan")
        table.add_column("Tryb")
        table.add_column("Stan")
        
        for idx, iface in enumerate(interfaces, 1):
            mode = self._get_interface_mode(iface)
            state = "UP" if self._is_interface_up(iface) else "DOWN"
            table.add_row(str(idx), iface, mode, state)
        
        self.console.print(table)
        
        while True:
            try:
                choice = Prompt.ask("Wybierz numer interfejsu", default="1")
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(interfaces):
                        return interfaces[idx]
                elif choice in interfaces:
                    return choice
                
                self.console.print("[yellow]Nieprawidłowy wybór. Spróbuj ponownie.[/yellow]")
            except KeyboardInterrupt:
                return ""

    def _start_engine(self) -> None:
        """Uruchamia emisję beaconów"""
        self._last_hop_ts = time.time()
        
        if self.simulate:
            return
        
        # Sprawdź czy mdk4 istnieje
        if not self._tool_exists("mdk4"):
            raise RuntimeError("mdk4 nie jest zainstalowany. Zainstaluj: sudo apt install mdk4")
        
        # Przygotuj plik z SSID
        self._ssid_list_file = f"/tmp/wifi_poet_{os.getpid()}.txt"
        with open(self._ssid_list_file, "w", encoding="utf-8") as f:
            for ap in self._fake_aps:
                f.write(f"{ap.ssid}\n")
        
        # Przygotuj komendę mdk4
        beacon_interval = max(10, min(1000, int(1000 / self.beacon_rate)))
        
        cmd = [
            "mdk4", self.interface, "b",
            "-c", str(self._current_channel),
            "-f", self._ssid_list_file,
            "-s", str(beacon_interval),
            "-m",
            "-t",
        ]
        
        if self.power_level > 0:
            cmd.extend(["-p", str(self.power_level)])
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                text=True,
                bufsize=1,
            )
            
            time.sleep(1.5)
            
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read() if self._proc.stderr else ""
                raise RuntimeError(f"mdk4 nie wystartował: {stderr}")
            
        except Exception as e:
            raise RuntimeError(f"Błąd uruchamiania mdk4: {e}")

    def _stop_engine(self) -> None:
        """Zatrzymuje emisję beaconów"""
        if self._proc:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=3)
            except:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
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
        """Rotacja kanałów"""
        if self.simulate:
            return
            
        now = time.time()
        if now - self._last_hop_ts < self.channel_hop_sec:
            return
        
        self._last_hop_ts = now
        
        try:
            current_idx = self.channels.index(self._current_channel)
            next_idx = (current_idx + 1) % len(self.channels)
            new_channel = self.channels[next_idx]
        except:
            new_channel = self.channels[0]
        
        if new_channel == self._current_channel:
            return
        
        self._current_channel = new_channel
        
        for ap in self._fake_aps:
            ap.channel = self._current_channel
        
        self.console.print(f"[cyan]Zmiana kanału na {self._current_channel}...[/cyan]")
        
        # Restart mdk4 z nowym kanałem
        if self._proc:
            self._stop_engine()
            time.sleep(1)
            self._start_engine()

    def _sleep_interruptible(self, seconds: float) -> None:
        """Czekanie z możliwością przerwania"""
        deadline = time.time() + max(0.0, seconds)
        while not self._stop_event.is_set():
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            time.sleep(min(0.2, remaining))

    def _mark_stopped(self) -> None:
        """Oznacza AP jako zatrzymane"""
        for ap in self._fake_aps:
            ap.status = "⏹️ STOPPED"

    def _build_view(self, elapsed: int):
        """Buduje widok na żywo"""
        # Panel statusu
        status_lines = [
            f"{'📡 RZECZYWISTY' if not self.simulate else '💻 SYMULACJA'}",
            f"📊 Wersów: {len(self._fake_aps)}",
            f"⏱️  Czas: {elapsed}s",
            f"📡 Interfejs: {self.interface}",
            f"📻 Kanał: {self._current_channel}",
        ]
        
        if not self.simulate and self._proc:
            status_lines.append(f"⚡ Szybkość: {self.beacon_rate}/s")
        
        header = Panel(
            "\n".join(status_lines),
            title="WiFi Poet",
            border_style="cyan",
        )
        
        # Tabela SSID
        table = Table(
            title="📜 Pan Tadeusz - Lista WiFi",
            title_style="bold green",
        )
        
        table.add_column("#", justify="right", width=3)
        table.add_column("SSID (wers z poematu)", width=50)
        table.add_column("BSSID", width=17)
        table.add_column("CH", justify="center", width=4)
        table.add_column("Status", width=10)
        
        visible = self._fake_aps[:self.max_rows]
        for i, ap in enumerate(visible, 1):
            table.add_row(
                str(i),
                ap.ssid,
                ap.bssid,
                str(ap.channel),
                ap.status,
            )
        
        if len(self._fake_aps) > self.max_rows:
            remaining = len(self._fake_aps) - self.max_rows
            table.add_row(
                "...",
                f"[dim]i {remaining} więcej...[/dim]",
                "",
                "",
                "",
            )
        
        # Wskazówka dla trybu rzeczywistego
        if not self.simulate and self._proc:
            tip = Panel(
                "📱 SPRAWDŹ TELEFON!\n"
                "Otwórz listę sieci Wi-Fi - zobaczysz fragmenty Pana Tadeusza.",
                title="📱 Wskazówka",
                border_style="yellow",
            )
            return Group(header, table, tip)
        
        return Group(header, table)

    def _render_summary(self, elapsed: int) -> None:
        """Wyświetla podsumowanie"""
        lines = [
            f"Status: {self.status.upper()}",
            f"Czas: {elapsed}s",
            f"Wysłano SSID: {len(self._fake_aps)}",
            f"Tryb: {'RZECZYWISTY' if not self.simulate else 'SYMULACJA'}",
            "",
            "Przykładowe wersy:",
        ]
        
        for i, ap in enumerate(self._fake_aps[:5], 1):
            lines.append(f"  {i}. {ap.ssid}")
        
        if self._error:
            lines.append(f"\nBłąd: {self._error}")
        
        lines.append(f"\n{LAB_DISCLAIMER}")
        
        self.console.print(Panel("\n".join(lines), title="Podsumowanie", border_style="green"))

    def _emit_webui_result(self, *, running: bool, elapsed_sec: int) -> None:
        """Emituje wyniki do WebUI"""
        if os.environ.get("SWISSKNIFE_WEBUI_TASK") != "1":
            return
        
        payload = {
            "kind": "wifi_poet",
            "running": running,
            "timestamp": int(time.time()),
            "status": self.status,
            "interface": self.interface,
            "duration": elapsed_sec,
            "simulate": self.simulate,
            "channel": self._current_channel,
            "device_count": len(self._fake_aps),
            "devices": [
                {
                    "ssid": ap.ssid,
                    "bssid": ap.bssid,
                    "channel": ap.channel,
                    "status": ap.status,
                }
                for ap in self._fake_aps[:10]  # Tylko pierwsze 10 dla WebUI
            ],
            "error": self._error,
        }
        
        print(f"[webui-result] {json.dumps(payload, ensure_ascii=False)}", flush=True)

    def _tool_exists(self, tool: str) -> bool:
        """Sprawdza czy narzędzie istnieje"""
        try:
            return subprocess.run(
                ["which", tool],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode == 0
        except:
            return False


def main():
    """Funkcja główna dla samodzielnego uruchomienia"""
    parser = argparse.ArgumentParser(description="WiFi Poet - Pan Tadeusz na liście WiFi")
    parser.add_argument("--interface", default="auto", help="Interfejs WiFi")
    parser.add_argument("--count", type=int, default=24, help="Liczba SSID")
    parser.add_argument("--duration", type=int, default=0, help="Czas trwania (s)")
    parser.add_argument("--no-simulate", dest="simulate", action="store_false", help="Tryb rzeczywisty")
    parser.add_argument("--channel-hop", type=float, default=15.0, help="Zmiana kanału co (s)")
    
    args = parser.parse_args()
    
    # Utwórz i skonfiguruj moduł
    module = WiFiPoet()
    module.configure(
        interface=args.interface,
        count=args.count,
        duration=args.duration,
        simulate=args.simulate,
        channel_hop_sec=args.channel_hop,
    )
    
    # Uruchom
    module.execute()


# Dla SwissKnife - eksportuj klasę
__all__ = ['WiFiPoet']

if __name__ == "__main__":
    main()