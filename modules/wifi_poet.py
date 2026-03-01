#!/usr/bin/env python3
"""
WiFi Poet module for SwissKnife.
Educational/lab demonstration of poem-based Wi-Fi beacon lists.
REAL TRANSMISSION MODE ONLY - uses mdk4 for beacon flood.
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
    # Fallback classes
    class Console:
        def print(self, *args, **kwargs): print(*args if args else '')
    class Panel:
        def __init__(self, renderable, **kwargs): self.renderable = renderable
        def __str__(self): return str(self.renderable) if self.renderable else ''
    class Table:
        def __init__(self, **kwargs): self.rows = []
        def add_column(self, name, **kwargs): pass
        def add_row(self, *vals): self.rows.append(vals)
        def __str__(self): return '\n'.join(str(r) for r in self.rows)
    class Group:
        def __init__(self, *objs): self.objs = objs
        def __str__(self): return "\n\n".join(str(o) for o in self.objs)
    class Live:
        def __init__(self, renderable, **kwargs): self.renderable = renderable
        def __enter__(self): print(self.renderable); return self
        def update(self, renderable, **kwargs): print(renderable)
        def __exit__(self, *args): pass
    class Prompt:
        @staticmethod
        def ask(prompt, default=None, **kwargs):
            sys.stdout.write(prompt + (f" [{default}]" if default else "") + ": ")
            sys.stdout.flush()
            return sys.stdin.readline().strip() or default or ''

# Import bazowego modułu SwissKnife
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

# Pan Tadeusz - pełna inwokacja
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

# Dodatkowe linie
EXTRA_LINES = [
    "Śród takich pól przed laty, nad błękitnym Niemnem",
    "Rosły, ach! rosły piękne dziecięce lata moje!",
    "I ojciec mój, w komorze, wesoły i szczęśliwy",
    "O przyszłości mej dumał, o przyszłości niwy.",
    "I matka, w wieńcu z jarzyn, w ogrodzie robiła",
    "I mnie, dziecinę, uczyła pacierza i szyła.",
]

DISCLAIMER = "⚠️  LABORATORIUM: Rzeczywista emisja beaconów WiFi. Tylko do użytku prywatnego."

@dataclass
class FakeAP:
    ssid: str
    bssid: str
    channel: int
    power: int = 0
    status: str = "📡 EMITUJE"

class WiFiPoet(Module):
    """Główna klasa modułu WiFi Poet - TYLKO TRYB RZECZYWISTY"""
    
    def __init__(self):
        super().__init__(name="WiFi Poet")
        
        # Parametry domyślne
        self.interface = "auto"
        self.original_interface = None  # zapamiętujemy oryginalną nazwę
        self.count = 24
        self.duration = 0
        self.refresh = 0.6
        self.seed = None
        self.channel = 6
        self.channels = [1, 6, 11]
        self.channel_hop_sec = 15.0
        self.max_rows = 12
        self.beacon_rate = 100
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
        self._monitor_interface = None  # nazwa interfejsu w trybie monitor
        
        self.console = Console()

    def configure(self, **kwargs):
        """Konfiguruje moduł"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        # Walidacja
        self.count = max(8, min(50, int(self.count)))
        self.refresh = max(0.2, float(self.refresh))
        self.channel = max(1, min(14, int(self.channel)))
        self.channels = [ch for ch in self.channels if 1 <= ch <= 14] or [self.channel]
        self.channel_hop_sec = max(3.0, float(self.channel_hop_sec))
        self.beacon_rate = max(20, min(1000, int(self.beacon_rate)))
        
        self._current_channel = self.channels[0]
        self._build_fake_aps()
        
        return self

    def execute(self) -> None:
        """Główna metoda uruchamiająca"""
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()

        # Sprawdź uprawnienia root
        if os.geteuid() != 0:
            self.status = "error"
            self._error = "WiFi Poet wymaga uprawnień root (sudo)."
            self.console.print(f"[red]{self._error}[/red]")
            self._restore_signal_handlers()
            return

        # Sprawdź czy mdk4 jest zainstalowany
        if not self._tool_exists("mdk4"):
            self.status = "error"
            self._error = "mdk4 nie jest zainstalowany. Zainstaluj: sudo apt install mdk4"
            self.console.print(f"[red]{self._error}[/red]")
            self._restore_signal_handlers()
            return

        # Wybierz interfejs (zapamiętujemy oryginalną nazwę)
        self.original_interface = self._select_interface()
        if not self.original_interface:
            self.status = "error"
            self._error = "Nie znaleziono interfejsu Wi-Fi."
            self.console.print(f"[red]{self._error}[/red]")
            self._restore_signal_handlers()
            return

        # Zapisz oryginalny tryb
        self._original_mode = self._get_interface_mode(self.original_interface)
        
        # Przełącz na tryb monitor - to może zmienić nazwę interfejsu!
        self.console.print(f"[yellow]Przełączanie {self.original_interface} w tryb monitor...[/yellow]")
        
        monitor_iface = self._enable_monitor_mode(self.original_interface)
        if not monitor_iface:
            self.status = "error"
            self._error = f"Nie udało się włączyć trybu monitor na {self.original_interface}."
            self.console.print(f"[red]{self._error}[/red]")
            self._restore_signal_handlers()
            return
        
        # Używamy interfejsu monitor do dalszej pracy
        self.interface = monitor_iface
        self._monitor_enabled = True
        self.console.print(f"[green]✓ Tryb monitor aktywny na {self.interface}[/green]")

        # Wyświetl nagłówek
        self.console.print(
            Panel.fit(
                "🔴 WiFi Poet - RZECZYWISTA EMISJA BEACONÓW\n"
                "Pan Tadeusz na liście sieci WiFi",
                border_style="red",
                title="⚠️  UWAGA",
            )
        )
        
        self.console.print("[bold red]🔴 EMISJA W ETERZE - sprawdź telefon![/bold red]")
        self.console.print(f"[dim]{DISCLAIMER}[/dim]")

        try:
            # Uruchom emisję
            self._start_engine()
            
            self.console.print("[bold green]✓ EMISJA AKTYWNA! Otwórz listę WiFi w telefonie.[/bold green]")
            self.console.print("[bold cyan]Naciśnij Ctrl+C aby zatrzymać.[/bold cyan]")
            
            # Główna pętla
            with Live(
                self._build_view(0),
                console=self.console,
                refresh_per_second=max(2, int(1.0 / self.refresh) + 1),
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
                        self._emit_webui_result(running=True, elapsed_sec=elapsed)
                        last_emit = now
                    
                    self._sleep_interruptible(self.refresh)
            
            self.status = "completed"
                
        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]Zatrzymywanie...[/yellow]")
        except Exception as exc:
            self.status = "error"
            self._error = str(exc)
            self.console.print(f"[red]Błąd: {exc}[/red]")
        finally:
            # Sprzątanie
            self.running = False
            self._stop_event.set()
            self._stop_engine()
            self._disable_monitor_mode()
            self._mark_stopped()
            elapsed = max(0, int(time.time() - started))
            self._render_summary(elapsed)
            self._emit_webui_result(running=False, elapsed_sec=elapsed)
            self._restore_signal_handlers()

    def _enable_monitor_mode(self, iface: str) -> Optional[str]:
        """
        Włącza tryb monitor i zwraca NAZWĘ interfejsu monitor.
        airmon-ng często zmienia nazwę na np. wlan1mon
        """
        # Sprawdź czy już jest w trybie monitor
        current_mode = self._get_interface_mode(iface).lower()
        if current_mode == "monitor":
            return iface
        
        # Metoda 1: airmon-ng (to zmienia nazwę interfejsu!)
        try:
            # Najpierw zabij procesy które mogą przeszkadzać
            subprocess.run(["airmon-ng", "check", "kill"], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         check=False)
            
            # Uruchom airmon-ng start
            result = subprocess.run(
                ["airmon-ng", "start", iface],
                capture_output=True,
                text=True,
                check=False,
            )
            
            if result.returncode == 0:
                # airmon-ng informuje o nowej nazwie interfejsu
                # Szukamy wzorca: "(monitor mode enabled on) wlan1mon"
                output = result.stdout + result.stderr
                
                # Różne wzorce które mogą wystąpić
                patterns = [
                    r"monitor mode enabled on (\w+)",
                    r"enabled on (\w+mon)",
                    r"\(mode enabled on\) (\w+)",
                    r"monitor mode vif enabled on (\w+)",
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        new_iface = match.group(1)
                        self.console.print(f"[green]✓ airmon-ng utworzył interfejs: {new_iface}[/green]")
                        return new_iface
                
                # Jeśli nie znaleźliśmy wzorca, ale airmon-ng succeeded,
                # spróbujmy znaleźć nowy interfejs przez iw dev
                time.sleep(1)  # daj czas na utworzenie
                interfaces = self._discover_wifi_interfaces()
                
                # Szukamy interfejsu który kończy się na "mon" lub zawiera "mon"
                for mon_iface in interfaces:
                    if mon_iface.endswith("mon") or "mon" in mon_iface:
                        if mon_iface != iface:  # inny niż oryginalny
                            self.console.print(f"[green]✓ Znaleziono interfejs monitor: {mon_iface}[/green]")
                            return mon_iface
        except Exception as e:
            self.console.print(f"[yellow]airmon-ng nie zadziałał: {e}[/yellow]")
        
        # Metoda 2: ręczne ustawienie (bez zmiany nazwy)
        self.console.print("[yellow]Próba ręcznego ustawienia trybu monitor...[/yellow]")
        try:
            # Wyłącz interfejs
            subprocess.run(["ip", "link", "set", iface, "down"], check=False)
            time.sleep(0.5)
            
            # Ustaw typ na monitor
            subprocess.run(
                ["iw", iface, "set", "type", "monitor"],
                check=False,
                capture_output=True,
            )
            
            # Włącz interfejs
            subprocess.run(["ip", "link", "set", iface, "up"], check=False)
            time.sleep(1)
            
            # Sprawdź czy się udało
            if self._get_interface_mode(iface).lower() == "monitor":
                self.console.print(f"[green]✓ Ręcznie ustawiono monitor na {iface}[/green]")
                return iface
        except Exception as e:
            self.console.print(f"[red]Ręczne ustawienie nie powiodło się: {e}[/red]")
        
        return None

    def _disable_monitor_mode(self) -> None:
        """Wyłącza tryb monitor i przywraca oryginalny interfejs"""
        if not self._monitor_enabled or not self.original_interface:
            return
        
        self.console.print("[yellow]Wyłączanie trybu monitor...[/yellow]")
        
        # Metoda 1: airmon-ng stop
        try:
            # Jeśli mamy interfejs monitor (np. wlan1mon)
            if self.interface and self.interface != self.original_interface:
                subprocess.run(
                    ["airmon-ng", "stop", self.interface],
                    capture_output=True,
                    check=False,
                )
                self.console.print(f"[green]✓ Zatrzymano {self.interface}[/green]")
        except:
            pass
        
        # Metoda 2: ręczne przywrócenie
        try:
            # Wyłącz interfejs monitor jeśli istnieje
            if self.interface and self.interface != self.original_interface:
                subprocess.run(["ip", "link", "set", self.interface, "down"], check=False)
            
            # Przywróć oryginalny interfejs
            subprocess.run(["ip", "link", "set", self.original_interface, "down"], check=False)
            time.sleep(0.5)
            
            # Ustaw tryb managed
            target = self._original_mode if self._original_mode != "unknown" else "managed"
            subprocess.run(
                ["iw", self.original_interface, "set", "type", target],
                check=False,
            )
            
            # Włącz interfejs
            subprocess.run(["ip", "link", "set", self.original_interface, "up"], check=False)
            self.console.print(f"[green]✓ Przywrócono {self.original_interface}[/green]")
        except Exception as e:
            self.console.print(f"[red]Błąd przy przywracaniu: {e}[/red]")
        
        # Przywróć menedżery sieci
        subprocess.run(["systemctl", "start", "NetworkManager"], 
                      stdout=subprocess.DEVNULL, 
                      stderr=subprocess.DEVNULL, 
                      check=False)
        
        self._monitor_enabled = False

    def _start_engine(self) -> None:
        """Uruchamia mdk4 do emisji beaconów"""
        self._last_hop_ts = time.time()
        
        # Przygotuj plik z SSID
        self._ssid_list_file = f"/tmp/wifi_poet_{os.getpid()}.txt"
        with open(self._ssid_list_file, "w", encoding="utf-8") as f:
            for ap in self._fake_aps:
                f.write(f"{ap.ssid}\n")
        
        # Oblicz interwał beaconów
        beacon_interval = max(10, min(1000, int(1000 / self.beacon_rate)))
        
        cmd = [
            "mdk4", self.interface, "b",
            "-c", str(self._current_channel),
            "-f", self._ssid_list_file,
            "-s", str(beacon_interval),
            "-m",  # spoof MAC
            "-t",  # używaj własnych BSSID
            "-w",  # WPA2
        ]
        
        if self.power_level > 0:
            cmd.extend(["-p", str(self.power_level)])
        
        self.console.print(f"[dim]Uruchamianie: {' '.join(cmd)}[/dim]")
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                text=True,
                bufsize=1,
            )
            
            time.sleep(2)
            
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read() if self._proc.stderr else ""
                raise RuntimeError(f"mdk4 nie wystartował: {stderr}")
            
            # Uruchom wątek monitorujący
            self._start_monitor_thread()
            
        except Exception as e:
            raise RuntimeError(f"Błąd uruchamiania mdk4: {e}")

    def _start_monitor_thread(self) -> None:
        """Monitoruje wyjście mdk4"""
        def monitor():
            if not self._proc or not self._proc.stderr:
                return
            for line in self._proc.stderr:
                if not line or self._stop_event.is_set():
                    break
                if "Packets sent" in line:
                    try:
                        packets = int(re.search(r'Packets sent: (\d+)', line).group(1))
                        self._packets_sent = packets
                    except:
                        pass
                elif "sent" in line.lower():
                    self._detected_by_scanner = True
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()

    def _build_view(self, elapsed: int):
        """Buduje widok na żywo"""
        status_lines = [
            f"🔴 EMISJA RZECZYWISTA - sprawdź telefon!",
            f"📊 Wersów: {len(self._fake_aps)}",
            f"⏱️  Czas: {elapsed}s",
            f"📡 Interfejs: {self.interface} (z {self.original_interface})",
            f"📻 Kanał: {self._current_channel}",
            f"⚡ Szybkość: {self.beacon_rate} beaconów/s",
            f"📦 Wysłano: ~{self._packets_sent} pakietów",
        ]
        
        if self._detected_by_scanner:
            status_lines.append("✅ WYKRYTO W ETERZE!")
        else:
            status_lines.append("📱 Skanuj WiFi w telefonie...")
        
        header = Panel(
            "\n".join(status_lines),
            title="🔴 WiFi Poet - AKTYWNY",
            border_style="red",
        )
        
        table = Table(title="📜 Pan Tadeusz na liście WiFi")
        table.add_column("#", width=3)
        table.add_column("SSID (wers z poematu)", width=50)
        table.add_column("BSSID", width=17)
        table.add_column("CH", width=4)
        table.add_column("Status", width=10)
        
        for i, ap in enumerate(self._fake_aps[:self.max_rows], 1):
            table.add_row(
                str(i),
                ap.ssid,
                ap.bssid,
                str(ap.channel),
                ap.status,
            )
        
        if len(self._fake_aps) > self.max_rows:
            table.add_row("...", f"+{len(self._fake_aps)-self.max_rows} więcej", "", "", "")
        
        tip = Panel(
            "📱 SPRAWDŹ TELEFON!\n"
            "Otwórz listę sieci Wi-Fi - zobaczysz fragmenty Pana Tadeusza.\n"
            "Odśwież listę kilka razy jeśli nie widzisz.",
            title="📱 Instrukcja",
            border_style="green",
        )
        
        return Group(header, table, tip)

    def _stop_engine(self) -> None:
        """Zatrzymuje mdk4"""
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

    def _build_fake_aps(self) -> None:
        """Buduje listę AP z fragmentami poematu"""
        all_lines = PAN_TADEUSZ_LINES + EXTRA_LINES
        selected = []
        
        for i in range(self.count):
            line = all_lines[i % len(all_lines)]
            if i >= len(PAN_TADEUSZ_LINES):
                line = f"[{i+1}] {line}"
            selected.append(line)
        
        rng = random.Random(self.seed if self.seed else int(time.time()))
        self._fake_aps = []
        
        for idx, ssid in enumerate(selected):
            mac = self._generate_mac(rng, idx)
            power = rng.randint(-67, -30)
            self._fake_aps.append(
                FakeAP(
                    ssid=ssid,
                    bssid=mac,
                    channel=self._current_channel,
                    power=power,
                )
            )

    def _generate_mac(self, rng: random.Random, offset: int) -> str:
        """Generuje adres MAC"""
        oui = [
            [0x02, 0x11, 0x22],
            [0x02, 0x14, 0xBF],
            [0x02, 0x18, 0xF8],
            [0x02, 0x1E, 0x52],
        ][offset % 4]
        
        octets = oui + [rng.randint(0, 255) for _ in range(3)]
        return ":".join(f"{b:02X}" for b in octets)

    def _discover_wifi_interfaces(self) -> List[str]:
        """Wykrywa interfejsy WiFi"""
        interfaces = []
        
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Interface" in line:
                        iface = line.split("Interface", 1)[1].strip()
                        if iface and iface not in interfaces:
                            interfaces.append(iface)
        except:
            pass
        
        return interfaces

    def _get_interface_mode(self, iface: str) -> str:
        """Sprawdza tryb interfejsu"""
        try:
            result = subprocess.run(
                ["iw", "dev", iface, "info"],
                capture_output=True,
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

    def _select_interface(self) -> str:
        """Wyświetla menu wyboru interfejsu"""
        interfaces = self._discover_wifi_interfaces()
        
        if not interfaces:
            return ""
        
        if self.interface and self.interface != "auto":
            return self.interface if self.interface in interfaces else ""
        
        if len(interfaces) == 1:
            return interfaces[0]
        
        # Wyświetl menu
        self.console.print("\n[dostępne interfejsy WiFi]")
        for i, iface in enumerate(interfaces, 1):
            mode = self._get_interface_mode(iface)
            self.console.print(f"  {i}. {iface} [{mode}]")
        
        while True:
            choice = Prompt.ask("Wybierz numer", default="1")
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]
            self.console.print("[yellow]Nieprawidłowy wybór[/yellow]")

    def _tool_exists(self, tool: str) -> bool:
        """Sprawdza czy narzędzie istnieje"""
        try:
            return subprocess.run(
                ["which", tool],
                capture_output=True,
                check=False,
            ).returncode == 0
        except:
            return False

    def _sleep_interruptible(self, seconds: float) -> None:
        """Czekanie z możliwością przerwania"""
        deadline = time.time() + seconds
        while not self._stop_event.is_set() and time.time() < deadline:
            time.sleep(0.1)

    def _tick_channel_rotation(self) -> None:
        """Rotacja kanałów"""
        now = time.time()
        if now - self._last_hop_ts < self.channel_hop_sec:
            return
        
        self._last_hop_ts = now
        
        try:
            idx = self.channels.index(self._current_channel)
            new_ch = self.channels[(idx + 1) % len(self.channels)]
        except:
            new_ch = self.channels[0]
        
        if new_ch == self._current_channel:
            return
        
        self._current_channel = new_ch
        
        for ap in self._fake_aps:
            ap.channel = self._current_channel
        
        self.console.print(f"[cyan]Zmiana kanału na {self._current_channel}[/cyan]")
        
        # Restart mdk4 z nowym kanałem
        if self._proc:
            self._stop_engine()
            time.sleep(1)
            self._start_engine()

    def _mark_stopped(self) -> None:
        for ap in self._fake_aps:
            ap.status = "⏹️ ZATRZYMANO"

    def _render_summary(self, elapsed: int) -> None:
        lines = [
            f"Status: {self.status}",
            f"Czas emisji: {elapsed}s",
            f"Wysłano wersów: {len(self._fake_aps)}",
            f"Przybliżona liczba pakietów: ~{self._packets_sent}",
            "",
            "Fragmenty które były emitowane:",
        ]
        
        for i, ap in enumerate(self._fake_aps[:5], 1):
            lines.append(f"  {i}. {ap.ssid}")
        
        lines.append(f"\n{DISCLAIMER}")
        
        self.console.print(Panel("\n".join(lines), title="Podsumowanie"))

    def _emit_webui_result(self, *, running: bool, elapsed_sec: int) -> None:
        if os.environ.get("SWISSKNIFE_WEBUI_TASK") != "1":
            return
        
        payload = {
            "kind": "wifi_poet",
            "running": running,
            "status": self.status,
            "interface": self.interface,
            "original_interface": self.original_interface,
            "duration": elapsed_sec,
            "channel": self._current_channel,
            "device_count": len(self._fake_aps),
            "packets_sent": self._packets_sent,
        }
        print(f"[webui-result] {json.dumps(payload)}", flush=True)

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
            except:
                pass

    def _restore_signal_handlers(self) -> None:
        for sig, prev in self._signal_handlers.items():
            try:
                signal.signal(sig, prev)
            except:
                pass

    def _handle_signal(self, signum, frame):
        self.stop()


def main():
    """Samodzielne uruchomienie"""
    parser = argparse.ArgumentParser(description="WiFi Poet - Pan Tadeusz na liście WiFi")
    parser.add_argument("--interface", default="auto", help="Interfejs WiFi")
    parser.add_argument("--count", type=int, default=24, help="Liczba SSID")
    parser.add_argument("--duration", type=int, default=0, help="Czas emisji (sekundy)")
    parser.add_argument("--channel-hop", type=float, default=15.0, help="Zmiana kanału co (s)")
    parser.add_argument("--beacon-rate", type=int, default=100, help="Beaconów na sekundę")
    
    args = parser.parse_args()
    
    module = WiFiPoet()
    module.configure(
        interface=args.interface,
        count=args.count,
        duration=args.duration,
        channel_hop_sec=args.channel_hop,
        beacon_rate=args.beacon_rate,
    )
    
    try:
        module.execute()
    except KeyboardInterrupt:
        module.stop()
        print("\nZatrzymano.")


__all__ = ['WiFiPoet']

if __name__ == "__main__":
    main()