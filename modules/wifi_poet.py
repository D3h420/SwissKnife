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
from typing import Dict, List, Optional, Set

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.layout import Layout
    from rich.text import Text
except ModuleNotFoundError:
    # (fallback classes pozostają bez zmian - zachowaj je z oryginału)
    pass

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

# Dodatkowe linie dla większej liczby SSID (jeśli ktoś chce więcej niż 22)
EXTRA_LINES = [
    "Śród takich pól przed laty, nad błękitnym Niemnem",
    "Rosły, ach! rosły piękne dziecięce lata moje!",
    "I ojciec mój, w komorze, wesoły i szczęśliwy",
    "O przyszłości mej dumał, o przyszłości niwy.",
    "I matka, w wieńcu z jarzyn, w ogrodzie robiła",
    "I mnie, dziecinę, uczyła pacierza i szyła.",
]

LAB_DISCLAIMER = "⚠️  Laboratorium: Tylko demonstracja beaconów. Żadna sieć nie umożliwia połączenia."

@dataclass
class FakeAP:
    ssid: str
    bssid: str
    channel: int
    power: int = 0  # symulowana moc sygnału
    status: str = "📡 ACTIVE"

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
        channel_hop_sec: float = 15.0,
        simulate: bool = True,
        max_rows: int = 12,
        beacon_rate: int = 50,  # liczba beaconów na sekundę
        power_level: int = 30,  # dBm (moc)
    ) -> None:
        super().__init__(name="WiFi Poet")
        self.interface = (interface or "auto").strip()
        self.count = max(8, min(50, int(count)))  # zwiększony max do 50
        self.duration = max(0, int(duration))
        self.refresh = max(0.2, float(refresh))
        self.seed = seed
        self.channel = max(1, min(14, int(channel)))
        self.channels = [ch for ch in (channels or [1, 6, 11]) if 1 <= ch <= 14] or [self.channel]
        self.channel_hop_sec = max(3.0, float(channel_hop_sec))  # krótszy hop dla lepszego efektu
        self.simulate = bool(simulate)
        self.max_rows = max(5, int(max_rows))
        self.beacon_rate = max(20, min(1000, int(beacon_rate)))
        self.power_level = max(0, min(100, int(power_level)))
        
        self.running = False
        self.status = "idle"
        self._stop_event = threading.Event()
        self._signal_handlers: Dict[int, object] = {}
        self._error: Optional[str] = None
        self._fake_aps: List[FakeAP] = []
        self._proc: Optional[subprocess.Popen] = None
        self._proc_monitor: Optional[subprocess.Popen] = None  # do monitorowania ruchu
        self._ssid_list_file: Optional[str] = None
        self._current_channel = self.channels[0]
        self._last_hop_ts = 0.0
        self._original_mode: str = "unknown"
        self._monitor_enabled = False
        self._packets_sent = 0
        self._detected_by_scanner = False  # flaga czy wykryto na skanerze
        
        self._build_fake_aps()

    def _build_fake_aps(self) -> None:
        """Buduje listę AP z zachowaniem kolejności dla efektu wiersza"""
        all_lines = PAN_TADEUSZ_LINES + EXTRA_LINES
        
        if self.seed is not None:
            rng = random.Random(self.seed)
            # Przy seedzie zachowujemy determinizm ale losujemy
            selected = rng.sample(all_lines, min(self.count, len(all_lines)))
        else:
            # Bez seeda - bierzemy po kolei dla czytelnego wiersza
            selected = []
            for i in range(self.count):
                line = all_lines[i % len(all_lines)]
                # Dodajemy numerację dla łatwiejszego śledzenia
                if i >= len(PAN_TADEUSZ_LINES):
                    line = f"[{i+1}] {line}"
                selected.append(line)
        
        rng_mac = random.Random(self.seed)
        self._fake_aps = []
        for idx, ssid in enumerate(selected):
            # Generuj MAC z zachowaniem local admin bit
            mac = self._generate_local_admin_mac(rng_mac, idx)
            # Symuluj moc sygnału (różne poziomy dla realizmu)
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
        """Generuje lokalny administracyjny MAC z użyciem OUI dla realizmu"""
        # Użyj popularnych OUI dla większego realizmu
        oui_list = [
            [0x00, 0x11, 0x22],  # Cisco
            [0x00, 0x14, 0xBF],  # Cisco
            [0x00, 0x18, 0xF8],  # Apple
            [0x00, 0x1E, 0x52],  # Samsung
            [0x00, 0x23, 0x76],  # Intel
            [0x00, 0x26, 0x5E],  # TP-Link
            [0x00, 0x27, 0x19],  # Asus
            [0x00, 0x40, 0x96],  # Intel
        ]
        
        # Wybierz OUI na podstawie seed_offset
        oui = oui_list[seed_offset % len(oui_list)].copy()
        
        # Ustaw bit lokalnego administrowania i indywidualnego adresu
        oui[0] = (oui[0] | 0x02) & 0xFE  # local admin, unicast
        
        # Generuj pozostałe 3 oktety
        octets = oui + [rng.randint(0, 255) for _ in range(3)]
        return ":".join(f"{b:02X}" for b in octets)

    def _discover_wifi_interfaces(self) -> List[str]:
        """Wykrywa interfejsy WiFi z większą dokładnością"""
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
        
        # Metoda 2: ip link show (fallback)
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
        
        # Metoda 3: ls /sys/class/net (dodatkowa)
        try:
            for iface in os.listdir("/sys/class/net"):
                if iface.startswith(("wlan", "wl", "wlp")):
                    if iface not in interfaces:
                        # Sprawdź czy to faktycznie WiFi
                        uevent_path = f"/sys/class/net/{iface}/device/uevent"
                        if os.path.exists(uevent_path):
                            with open(uevent_path, 'r') as f:
                                if 'WiFi' in f.read() or 'wlan' in f.read():
                                    interfaces.append(iface)
        except (FileNotFoundError, PermissionError):
            pass
        
        return interfaces

    def _ensure_monitor_mode(self, iface: str) -> bool:
        """Ulepszone przełączanie w tryb monitor z obsługą NetworkManager"""
        current_mode = self._get_interface_mode(iface).lower()
        
        if current_mode == "monitor":
            self._monitor_enabled = True
            self.console.print(f"[green]✓ Interface {iface} already in monitor mode[/green]")
            return True
        
        self.console.print(f"[yellow]Switching {iface} to monitor mode...[/yellow]")
        
        # Zatrzymaj usługi które mogą przeszkadzać
        for service in ["NetworkManager", "wpa_supplicant"]:
            subprocess.run(
                ["systemctl", "stop", service],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        
        # Wyłącz interfejs
        subprocess.run(["ip", "link", "set", iface, "down"], check=False)
        time.sleep(0.5)
        
        # Spróbuj użyć airmon-ng jeśli dostępny
        airmon_result = subprocess.run(
            ["airmon-ng", "start", iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        
        if airmon_result.returncode == 0:
            # airmon-ng tworzy nowy interfejs (zwykle z końcówką "mon")
            for line in airmon_result.stdout.splitlines():
                if "monitor mode enabled on" in line:
                    mon_iface = line.split("on")[-1].strip()
                    self.console.print(f"[green]✓ Created monitor interface: {mon_iface}[/green]")
                    self.interface = mon_iface
                    self._monitor_enabled = True
                    return True
        
        # Fallback: ręczne ustawienie trybu monitor
        self.console.print("[yellow]Falling back to manual monitor mode setup...[/yellow]")
        
        # Usuń istniejące tryby monitor
        subprocess.run(["iw", iface, "set", "type", "managed"], check=False)
        time.sleep(0.3)
        
        # Ustaw tryb monitor
        result = subprocess.run(
            ["iw", iface, "set", "type", "monitor"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        
        if result.returncode != 0:
            self.console.print(f"[red]Failed to set monitor mode: {result.stderr}[/red]")
            # Przywróć interfejs
            subprocess.run(["ip", "link", "set", iface, "up"], check=False)
            return False
        
        # Dodatkowe flagi monitora dla lepszej kompatybilności
        subprocess.run(
            ["iw", iface, "set", "monitor", "control", "otherbss"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        
        # Włącz interfejs
        subprocess.run(["ip", "link", "set", iface, "up"], check=False)
        time.sleep(1)
        
        # Weryfikacja
        new_mode = self._get_interface_mode(iface).lower()
        if new_mode == "monitor":
            self._monitor_enabled = True
            self.console.print(f"[green]✓ {iface} successfully switched to monitor mode[/green]")
            return True
        else:
            self.console.print(f"[red]✗ Failed to verify monitor mode on {iface}[/red]")
            return False

    def _restore_interface_mode(self) -> None:
        """Przywraca oryginalny tryb interfejsu"""
        if not self.interface or not self._monitor_enabled:
            return
        
        self.console.print("[yellow]Restoring network interfaces...[/yellow]")
        
        # Jeśli używaliśmy airmon-ng, użyj go do przywrócenia
        subprocess.run(
            ["airmon-ng", "stop", self.interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        
        # Wyłącz interfejs
        subprocess.run(["ip", "link", "set", self.interface, "down"], check=False)
        time.sleep(0.5)
        
        # Przywróć tryb managed
        if self._original_mode and self._original_mode != "unknown":
            target_mode = self._original_mode
        else:
            target_mode = "managed"
        
        subprocess.run(
            ["iw", self.interface, "set", "type", target_mode],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        
        # Włącz interfejs
        subprocess.run(["ip", "link", "set", self.interface, "up"], check=False)
        
        # Przywróć usługi
        for service in ["NetworkManager", "wpa_supplicant"]:
            subprocess.run(
                ["systemctl", "start", service],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        
        self._monitor_enabled = False
        self.console.print("[green]✓ Network interfaces restored[/green]")

    def _start_engine(self) -> None:
        """Ulepszone uruchamianie emisji beaconów"""
        self._last_hop_ts = time.time()
        
        if self.simulate:
            self.console.print("[yellow][SIMULATED MODE] No real RF transmission.[/yellow]")
            return

        if not self._tool_exists("mdk4"):
            raise RuntimeError("❌ mdk4 not found. Install it: sudo apt install mdk4")

        self.console.print("[bold cyan]Preparing beacon flood...[/bold cyan]")
        
        # Przygotuj plik z SSID (upewnij się że są w dobrej kolejności)
        self._ssid_list_file = f"/tmp/wifi_poet_ssids_{os.getpid()}.txt"
        with open(self._ssid_list_file, "w", encoding="utf-8") as f:
            for i, ap in enumerate(self._fake_aps, 1):
                # Dodaj znacznik kolejności dla debug
                f.write(f"{ap.ssid}\n")
        
        self.console.print(f"[dim]✓ SSID list saved ({len(self._fake_aps)} entries)[/dim]")
        
        # Oblicz interwał beaconów (w ms) dla pożądanej szybkości
        # 1000 ms / beacon_rate = interwał w ms
        beacon_interval = max(10, min(1000, int(1000 / self.beacon_rate)))
        
        # Podstawowe parametry dla mdk4
        cmd = [
            "mdk4", self.interface, "b",
            "-c", str(self._current_channel),
            "-f", self._ssid_list_file,
            "-s", str(beacon_interval),  # szybkość beaconów
            "-m",  # spoof MAC
            "-t",  # użyj własnych BSSID (z naszej listy)
        ]
        
        # Dodaj parametry mocy jeśli podano
        if self.power_level > 0:
            cmd.extend(["-p", str(self.power_level)])
        
        self.console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")
        
        try:
            # Uruchom mdk4
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                text=True,
                bufsize=1,  # linia po linii
            )
            
            # Uruchom monitor wątku do czytania wyjścia mdk4
            self._start_monitor_thread()
            
            # Daj czas na start
            time.sleep(2)
            
            # Sprawdź czy proces żyje
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read() if self._proc.stderr else ""
                raise RuntimeError(f"mdk4 failed: {stderr}")
            
            self.console.print("[bold green]✓ Beacon flood ACTIVE! Check your phone's WiFi list![/bold green]")
            self.console.print("[dim]Press Ctrl+C to stop[/dim]")
            
        except Exception as e:
            raise RuntimeError(f"Failed to start beacon flood: {e}")

    def _start_monitor_thread(self) -> None:
        """Monitoruje wyjście mdk4 i aktualizuje statystyki"""
        def monitor_output():
            if not self._proc or not self._proc.stderr:
                return
            
            for line in self._proc.stderr:
                if not line or self._stop_event.is_set():
                    break
                
                # Parsuj linie z mdk4 dla statystyk
                if "Packets sent" in line:
                    try:
                        packets = int(re.search(r'Packets sent: (\d+)', line).group(1))
                        self._packets_sent = packets
                    except:
                        pass
                elif "beacon" in line.lower():
                    # Wykryto wysłanie beaconów
                    self._detected_by_scanner = True
        
        thread = threading.Thread(target=monitor_output, daemon=True)
        thread.start()

    def _stop_engine(self) -> None:
        """Zatrzymuje emisję beaconów"""
        if self._proc:
            try:
                # Wyślij SIGTERM do całej grupy procesów
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=3)
            except:
                # Jeśli nie zadziała, zabij brutalnie
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
                except:
                    pass
            self._proc = None
        
        # Usuń plik tymczasowy
        if self._ssid_list_file and os.path.exists(self._ssid_list_file):
            try:
                os.remove(self._ssid_list_file)
            except:
                pass
            self._ssid_list_file = None

    def _tick_channel_rotation(self) -> None:
        """Ulepszona rotacja kanałów z restartem mdk4"""
        now = time.time()
        if now - self._last_hop_ts < self.channel_hop_sec:
            return
        
        self._last_hop_ts = now
        
        # Wybierz następny kanał
        try:
            current_idx = self.channels.index(self._current_channel)
            next_idx = (current_idx + 1) % len(self.channels)
        except ValueError:
            next_idx = 0
        
        new_channel = self.channels[next_idx]
        
        if new_channel == self._current_channel:
            return
        
        self._current_channel = new_channel
        
        # Aktualizuj kanał w AP
        for ap in self._fake_aps:
            ap.channel = self._current_channel
        
        self.console.print(f"[cyan]Switching to channel {self._current_channel}...[/cyan]")
        
        # W trybie rzeczywistym restartuj mdk4 z nowym kanałem
        if not self.simulate and self._proc:
            self._stop_engine()
            time.sleep(1)  # Daj czas na zwolnienie kanału
            self._start_engine()

    def _verify_beacon_visibility(self) -> bool:
        """Sprawdza czy beacony są widoczne (opcjonalnie)"""
        if self.simulate:
            return False
        
        # Użyj tcpdump lub airodump do sprawdzenia
        check_cmd = [
            "timeout", "2",
            "tcpdump", "-i", self.interface,
            "-c", "5",  # złap 5 beaconów
            "type", "mgt", "subtype", "beacon",
            "-e",  # pokaż MAC
            "-q"   # quiet
        ]
        
        try:
            result = subprocess.run(
                check_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
            return result.returncode == 0
        except:
            return False

    def _build_view(self, elapsed: int):
        """Rozszerzony widok z lepszym formatowaniem"""
        # Panel statusu
        status_lines = [
            f"[bold]{'📡 REAL' if not self.simulate else '💻 SIMULATED'} MODE[/bold]",
            f"📊 Entries: {len(self._fake_aps)}",
            f"⏱️  Elapsed: {elapsed}s",
            f"📡 Interface: {self.interface}",
            f"📻 Channel: {self._current_channel} (hop: {int(self.channel_hop_sec)}s)",
        ]
        
        if not self.simulate:
            status_lines.extend([
                f"📦 Packets sent: {self._packets_sent}",
                f"📱 Detected: {'✅ YES' if self._detected_by_scanner else '⏳ scanning...'}",
                f"⚡ Beacon rate: {self.beacon_rate}/s",
            ])
        
        header = Panel(
            "\n".join(status_lines),
            title="WiFi Poet Status",
            border_style="cyan",
        )
        
        # Tabela SSID
        table = Table(
            title="📜 Pan Tadeusz - WiFi Edition",
            title_style="bold green",
            header_style="bold cyan",
            border_style="blue",
        )
        
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("SSID (wers z poematu)", style="bold white", width=50)
        table.add_column("BSSID", style="dim magenta", width=17)
        table.add_column("CH", justify="center", width=4)
        table.add_column("Signal", justify="center", width=8)
        table.add_column("Status", width=10)
        
        visible = self._fake_aps[:self.max_rows]
        for i, ap in enumerate(visible, 1):
            # Formatuj moc sygnału
            signal_str = f"{ap.power} dBm" if ap.power else "N/A"
            if ap.power > -50:
                signal_str = f"📶 {ap.power}"
            elif ap.power > -70:
                signal_str = f"📡 {ap.power}"
            else:
                signal_str = f"📻 {ap.power}"
            
            table.add_row(
                str(i),
                ap.ssid,
                ap.bssid,
                str(ap.channel),
                signal_str,
                ap.status,
            )
        
        if len(self._fake_aps) > self.max_rows:
            remaining = len(self._fake_aps) - self.max_rows
            table.add_row(
                "...",
                f"[dim]and {remaining} more verses...[/dim]",
                "",
                "",
                "",
                "",
            )
        
        # Dodaj panel z instrukcją
        if not self.simulate and not self._detected_by_scanner:
            tip = Panel(
                "[bold yellow]📱 SPRAWDŹ TELEFON![/bold yellow]\n"
                "Otwórz listę sieci Wi-Fi w telefonie. "
                "Powinieneś zobaczyć fragmenty 'Pana Tadeusza' jako nazwy sieci.\n"
                "Jeśli nie widzisz:\n"
                "• Odśwież listę kilka razy\n"
                "• Sprawdź czy jesteś w zasięgu\n"
                "• Upewnij się że kanał {self._current_channel} jest wspierany przez telefon",
                title="📱 Visibility Check",
                border_style="yellow",
            )
            return Group(header, table, tip)
        
        return Group(header, table)

    def _render_summary(self, elapsed: int) -> None:
        """Podsumowanie po zakończeniu"""
        lines = [
            f"[bold]WiFi Poet Summary[/bold]",
            f"Status: {self.status.upper()}",
            f"Runtime: {elapsed}s",
            f"SSIDs broadcast: {len(self._fake_aps)}",
            f"Mode: {'REAL' if not self.simulate else 'SIMULATED'}",
            f"Packets sent: {self._packets_sent}",
        ]
        
        if not self.simulate:
            if self._detected_by_scanner:
                lines.append("[green]✓ Beacony were detected in the air[/green]")
            else:
                lines.append("[yellow]⚠️  No beacon detection confirmed[/yellow]")
        
        lines.extend([
            "",
            "[dim]Sample verses broadcast:[/dim]",
        ])
        
        for i, ap in enumerate(self._fake_aps[:5], 1):
            lines.append(f"  {i}. {ap.ssid}")
        
        if self._error:
            lines.append(f"\n[red]Error: {self._error}[/red]")
        
        lines.append(f"\n[dim]{LAB_DISCLAIMER}[/dim]")
        
        self.console.print(Panel("\n".join(lines), border_style="green"))

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
            "disclaimer": LAB_DISCLAIMER,
            "channel": self._current_channel,
            "channels": self.channels,
            "packets_sent": self._packets_sent,
            "detected": self._detected_by_scanner,
            "device_count": len(self._fake_aps),
            "devices": [
                {
                    "ssid": ap.ssid,
                    "bssid": ap.bssid,
                    "channel": ap.channel,
                    "power": ap.power,
                    "status": ap.status,
                }
                for ap in self._fake_aps
            ],
            "error": self._error,
        }
        print(f"[webui-result] {json.dumps(payload, ensure_ascii=False)}", flush=True)

    # Pozostałe metody pomocnicze (bez zmian)
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
        for line in result.stdout.splitlines():
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

    def _tool_exists(self, tool: str) -> bool:
        return subprocess.run(
            ["which", tool],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0

    def _sleep_interruptible(self, seconds: float) -> None:
        deadline = time.time() + max(0.0, seconds)
        while not self._stop_event.is_set():
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            time.sleep(min(0.2, remaining))

    def _mark_stopped(self) -> None:
        for ap in self._fake_aps:
            ap.status = "⏹️ STOPPED"


def parse_channels(raw: str) -> List[int]:
    """Parsuje listę kanałów z stringa"""
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
    """Parsuje argumenty linii poleceń"""
    parser = argparse.ArgumentParser(
        description="WiFi Poet - wyświetl Pana Tadeusza na liście Wi-Fi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Przykłady:
  %(prog)s --simulate                    # tryb symulacji (domyślny)
  %(prog)s --no-simulate --interface wlan0  # prawdziwa emisja
  %(prog)s --no-simulate --count 30 --channel-hop 10  # 30 wersów, zmiana kanału co 10s
  %(prog)s --no-simulate --beacon-rate 200  # szybka emisja (200 beaconów/s)
        """
    )
    
    parser.add_argument(
        "--interface", 
        default="auto", 
        help="Interfejs Wi-Fi (domyślnie: auto)"
    )
    
    parser.add_argument(
        "--count", 
        type=int, 
        default=24, 
        help="Liczba SSID (wersów poematu) (8-50, domyślnie: 24)"
    )
    
    parser.add_argument(
        "--duration", 
        type=int, 
        default=0, 
        help="Czas działania w sekundach (0 = bez ograniczenia)"
    )
    
    parser.add_argument(
        "--refresh", 
        type=float, 
        default=0.6, 
        help="Odświeżanie widoku w sekundach"
    )
    
    parser.add_argument(
        "--seed", 
        type=int, 
        default=None, 
        help="Ziarno losowości dla deterministycznych wyników"
    )
    
    parser.add_argument(
        "--channel", 
        type=int, 
        default=6, 
        help="Domyślny kanał Wi-Fi (1-14)"
    )
    
    parser.add_argument(
        "--channels", 
        default="1,6,11", 
        help="Lista kanałów do rotacji, np. 1,6,11"
    )
    
    parser.add_argument(
        "--channel-hop", 
        type=float, 
        default=15.0, 
        help="Interwał zmiany kanału w sekundach"
    )
    
    parser.add_argument(
        "--max-rows", 
        type=int, 
        default=12, 
        help="Maksymalna liczba wierszy w tabeli na żywo"
    )
    
    parser.add_argument(
        "--beacon-rate", 
        type=int, 
        default=50, 
        help="Liczba beaconów na sekundę (20-1000)"
    )
    
    parser.add_argument(
        "--power", 
        type=int, 
        default=30, 
        help="Moc nadawania w dBm (0-100)"
    )
    
    parser.add_argument(
        "--simulate", 
        dest="simulate", 
        action="store_true", 
        default=True, 
        help="Tryb symulacji (domyślny)"
    )
    
    parser.add_argument(
        "--no-simulate", 
        dest="simulate", 
        action="store_false", 
        help="Tryb rzeczywisty - emituj beacony przez mdk4"
    )
    
    return parser.parse_args()


def check_prerequisites(args) -> bool:
    """Sprawdza czy wszystkie wymagania są spełnione przed uruchomieniem"""
    if args.simulate:
        return True
    
    print("🔍 Checking prerequisites for REAL mode...")
    
    # Sprawdź uprawnienia root
    if os.geteuid() != 0:
        print("❌ REAL mode requires root privileges. Run with sudo.")
        return False
    
    # Sprawdź czy mdk4 istnieje
    mdk4_check = subprocess.run(
        ["which", "mdk4"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if mdk4_check.returncode != 0:
        print("❌ mdk4 not found. Install it:")
        print("   sudo apt update && sudo apt install mdk4")
        return False
    
    # Sprawdź czy airmon-ng istnieje (opcjonalnie)
    airmon_check = subprocess.run(
        ["which", "airmon-ng"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if airmon_check.returncode != 0:
        print("⚠️  airmon-ng not found. Monitor mode setup may be limited.")
        print("   Install aircrack-ng: sudo apt install aircrack-ng")
    
    print("✅ Prerequisites satisfied!")
    return True


def main() -> None:
    """Funkcja główna"""
    args = parse_args()
    
    # Sprawdź wymagania przed uruchomieniem
    if not check_prerequisites(args):
        sys.exit(1)
    
    # Komunikat ostrzegawczy dla trybu rzeczywistego
    if not args.simulate:
        print("\n" + "="*60)
        print("🔴 UWAGA: TRYB RZECZYWISTY - EMISJA BEACONÓW!")
        print("="*60)
        print("• Będziesz nadawać prawdziwe ramki Wi-Fi")
        print("• Upewnij się że masz pozwolenie na korzystanie z widma")
        print("• Używaj tylko we własnym laboratorium")
        print("• Po zakończeniu interfejs wróci do normalnego trybu")
        print("="*60 + "\n")
        
        response = input("Czy kontynuować? (tak/NIE): ").strip().lower()
        if response != "tak":
            print("Anulowano.")
            sys.exit(0)
    
    # Utwórz i uruchom moduł
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
        beacon_rate=args.beacon_rate,
        power_level=args.power,
    )
    
    try:
        module.run()
    except KeyboardInterrupt:
        print("\n\nZatrzymywanie WiFi Poet...")
        module.stop()
    except Exception as e:
        print(f"\n❌ Błąd: {e}")
        module.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()