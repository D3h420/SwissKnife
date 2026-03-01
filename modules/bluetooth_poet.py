#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import random
import signal
import sys
import threading
import time
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional
try:
    from rich import box
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
except ModuleNotFoundError:
    # Fallback so module remains usable without rich.
    RICH_AVAILABLE = False
    class Console: # type: ignore[override]
        def print(self, *objects: object, **_kwargs: object) -> None:
            print(*objects)
    class _FallbackBox:
        SIMPLE_HEAVY = None
    box = _FallbackBox() # type: ignore[assignment]
    class Panel: # type: ignore[override]
        def __init__(self, renderable: object, title: str = "", border_style: str = "") -> None:
            self.renderable = renderable
            self.title = title
            self.border_style = border_style
        @classmethod
        def fit(cls, renderable: object, **kwargs: object):
            return cls(renderable, **kwargs)
        def __str__(self) -> str:
            if self.title:
                return f"{self.title}\n{self.renderable}"
            return str(self.renderable)
    class Table: # type: ignore[override]
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
    class Group: # type: ignore[override]
        def __init__(self, *objects: object) -> None:
            self.objects = objects
        def __str__(self) -> str:
            return "\n\n".join(str(item) for item in self.objects)
    class Live: # type: ignore[override]
        def __init__(
            self,
            renderable: object,
            console: Optional[Console] = None,
            refresh_per_second: float = 4,
            transient: bool = False,
        ) -> None:
            del refresh_per_second, transient
            self.renderable = renderable
            self.console = console or Console()
        def __enter__(self) -> "Live":
            self.console.print(self.renderable)
            return self
        def update(self, renderable: object, refresh: bool = False) -> None:
            del refresh
            self.renderable = renderable
            self.console.print(renderable)
        def __exit__(self, _exc_type, _exc, _tb) -> bool:
            return False
try:
    from core.module import Module # type: ignore
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
import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib as GObject  # Use GLib for mainloop

PAN_TADEUSZ_INVOKACJA = """
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

BLUEZ_SERVICE_NAME = 'org.bluez'
LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'
LE_ADVERTISEMENT_IFACE = 'org.bluez.LEAdvertisement1'

class InvalidArgsException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'

class NotSupportedException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.bluez.Error.NotSupported'

class NotPermittedException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.bluez.Error.NotPermitted'

class InvalidValueLengthException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.bluez.Error.InvalidValueLength'

class FailedException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.bluez.Error.Failed'

@dataclass
class SimulatedBeacon:
    name: str
    mac: str
    rssi: int
    status: str = "ACTIVE"

def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))

def clean_poem_lines(text: str) -> List[str]:
    rows: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line:
            rows.append(line)
    return rows

class Advertisement(dbus.service.Object):
    PATH_BASE = '/org/bluez/example/advertisement'

    def __init__(self, bus, index, advertising_type, local_name):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.ad_type = advertising_type
        self.service_uuids = None
        self.manufacturer_data = None
        self.solicit_uuids = None
        self.service_data = None
        self.local_name = local_name
        self.include_tx_power = True
        self.data = None
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        properties = dict()
        properties['Type'] = self.ad_type
        if self.service_uuids is not None:
            properties['ServiceUUIDs'] = dbus.Array(self.service_uuids, signature='s')
        if self.solicit_uuids is not None:
            properties['SolicitUUIDs'] = dbus.Array(self.solicit_uuids, signature='s')
        if self.manufacturer_data is not None:
            properties['ManufacturerData'] = dbus.Dictionary(self.manufacturer_data, signature='qv')
        if self.service_data is not None:
            properties['ServiceData'] = dbus.Dictionary(self.service_data, signature='sv')
        if self.local_name is not None:
            properties['LocalName'] = dbus.String(self.local_name)
        if self.include_tx_power:
            properties['Includes'] = dbus.Array(["tx-power"], signature='s')
        if self.data is not None:
            properties['Data'] = dbus.Dictionary(self.data, signature='yv')
        return {LE_ADVERTISEMENT_IFACE: properties}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != LE_ADVERTISEMENT_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[LE_ADVERTISEMENT_IFACE]

    @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature='', out_signature='')
    def Release(self):
        pass  # No-op for simplicity

class BluetoothPoet(Module):
    def __init__(
        self,
        *,
        count: int = 24,
        duration: int = 60,
        refresh_interval: float = 1.0,
        seed: Optional[int] = None,
        mac_prefix: str = "00:00:00",
        interface: str = "hci0",
        advertise_interval: float = 0.5,  # Time to advertise each "device"
    ) -> None:
        super().__init__(name="Bluetooth Poet")
        self.count = clamp(int(count), 20, 30)
        self.duration = max(0, int(duration))
        self.refresh_interval = max(0.2, float(refresh_interval))
        self.seed = seed
        self.mac_prefix = mac_prefix.strip() or "00:00:00"
        self.interface = interface.strip() or "hci0"
        self.advertise_interval = max(0.1, float(advertise_interval))
        self.poem_lines = clean_poem_lines(PAN_TADEUSZ_INVOKACJA)
        self.running = False
        self.status = "idle"
        self._stop_event = threading.Event()
        self._signal_handlers: Dict[int, object] = {}
        self._beacons: List[SimulatedBeacon] = []
        self._error: Optional[str] = None
        self.bus = None
        self.ad_manager = None
        self.current_ad = None

    def run(self) -> None:
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()
        self.console.print(
            Panel.fit(
                "BluetoothPoet (tryb laboratoryjny)\nRealne nadawanie beaconów BLE w kontrolowanym środowisku.",
                border_style="cyan",
                title="SwissKnife",
            )
        )
        self.console.print(
            "[yellow]Używaj TYLKO w kontrolowanym laboratorium na własnych urządzeniach. Może wymagać bdaddr tool do zmiany MAC.[/yellow]"
        )
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self.bus = dbus.SystemBus()
        adapter = self.find_adapter(self.bus)
        if not adapter:
            self._error = 'LEAdvertisingManager1 interface not found'
            self.status = "error"
            self.running = False
            return
        adapter_props = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, adapter), DBUS_PROP_IFACE)
        adapter_props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(1))
        self.ad_manager = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, adapter), LE_ADVERTISING_MANAGER_IFACE)
        try:
            self._beacons = self._build_simulated_beacons()  # For display purposes
            self.console.print(
                "[bold cyan]Nadawanie beaconów BLE z wierszem Mickiewicza w toku (tryb laboratoryjny) — Ctrl+C aby zatrzymać[/bold cyan]"
            )
            with Live(
                self._build_live_view(0),
                console=self.console,
                refresh_per_second=max(2, int(1 / self.refresh_interval) + 1),
                transient=False,
            ) as live:
                last_emit = 0.0
                index = 0
                while not self._stop_event.is_set():
                    elapsed = int(time.time() - started)
                    if self.duration > 0 and elapsed >= self.duration:
                        break
                    # Cycle through poem lines
                    name = self.poem_lines[index % len(self.poem_lines)]
                    mac = self._make_mac(index, random.Random(self.seed))
                    # Try to change MAC (requires bdaddr tool and root)
                    try:
                        self.change_mac(mac)
                    except Exception as e:
                        self.console.print(f"[yellow]Nie udało się zmienić MAC: {e}. Kontynuuję z bieżącym MAC.[/yellow]")
                    # Create and register advertisement
                    self.current_ad = Advertisement(self.bus, index, 'peripheral', name)
                    self.ad_manager.RegisterAdvertisement(self.current_ad.get_path(), {},
                                                          reply_handler=lambda: print('Advertisement registered'),
                                                          error_handler=lambda e: print('Failed to register: ' + str(e)))
                    time.sleep(self.advertise_interval)
                    # Unregister
                    self.ad_manager.UnregisterAdvertisement(self.current_ad.get_path())
                    dbus.service.Object.remove_from_connection(self.current_ad)
                    index += 1
                    self._update_fake_rssi()
                    live.update(self._build_live_view(elapsed), refresh=True)
                    now = time.time()
                    if now - last_emit >= 1.0:
                        self._emit_webui_result(running=True, elapsed_sec=elapsed)
                        last_emit = now
                    self._sleep_interruptible(self.refresh_interval)
            self.status = "completed"
        except KeyboardInterrupt:
            self.status = "stopped"
            self.console.print("\n[yellow]BluetoothPoet interrupted by user.[/yellow]")
        except Exception as exc:
            self.status = "error"
            self._error = str(exc)
            self.console.print(f"[red]BluetoothPoet error:[/red] {exc}")
        finally:
            self.running = False
            self._stop_event.set()
            if self.current_ad:
                try:
                    self.ad_manager.UnregisterAdvertisement(self.current_ad.get_path())
                    dbus.service.Object.remove_from_connection(self.current_ad)
                except:
                    pass
            elapsed = max(0, int(time.time() - started))
            self._mark_beacons_stopped()
            self._render_summary(elapsed)
            self._emit_webui_result(running=False, elapsed_sec=elapsed)
            self._restore_signal_handlers()

    def stop(self) -> None:
        self.running = False
        self.status = "stopped"
        self._stop_event.set()
        self.console.print("[yellow]Stopping BluetoothPoet...[/yellow]")

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

    def _sleep_interruptible(self, seconds: float) -> None:
        deadline = time.time() + max(0.0, seconds)
        while not self._stop_event.is_set():
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            time.sleep(min(0.2, remaining))

    def find_adapter(self, bus):
        remote_om = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, '/'), DBUS_OM_IFACE)
        objects = remote_om.GetManagedObjects()
        for o, props in objects.items():
            if LE_ADVERTISING_MANAGER_IFACE in props:
                return o
        return None

    def change_mac(self, new_mac):
        # Use subprocess to change MAC using hciconfig and bdaddr
        subprocess.check_call(["hciconfig", self.interface, "down"])
        subprocess.check_call(["bdaddr", "-i", self.interface, new_mac])
        subprocess.check_call(["hciconfig", self.interface, "up"])

    def _build_simulated_beacons(self) -> List[SimulatedBeacon]:
        if not self.poem_lines:
            raise RuntimeError("Brak linijek tekstu do symulacji nazw BLE.")
        rng = random.Random(self.seed)
        beacons: List[SimulatedBeacon] = []
        for index in range(self.count):
            name = self.poem_lines[index % len(self.poem_lines)]
            mac = self._make_mac(index, rng)
            rssi = rng.randint(-88, -42)
            beacons.append(SimulatedBeacon(name=name, mac=mac, rssi=rssi))
        return beacons

    def _make_mac(self, index: int, rng: random.Random) -> str:
        prefix_parts = [part.strip() for part in self.mac_prefix.split(":") if part.strip()]
        prefix_octets: List[int] = []
        for part in prefix_parts[:3]:
            try:
                prefix_octets.append(int(part, 16) & 0xFF)
            except ValueError:
                prefix_octets.append(0x00)
        while len(prefix_octets) < 3:
            prefix_octets.append(0x00)
        suffix = [rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255)]
        octets = prefix_octets + suffix
        return ":".join(f"{value:02X}" for value in octets)

    def _update_fake_rssi(self) -> None:
        rng = random.Random()
        for beacon in self._beacons:
            beacon.rssi = clamp(beacon.rssi + rng.randint(-2, 2), -95, -35)

    def _mark_beacons_stopped(self) -> None:
        for beacon in self._beacons:
            beacon.status = "STOPPED"

    def _build_device_table(self) -> Table:
        table = Table(title="Nadawane beacony BLE", box=box.SIMPLE_HEAVY)
        table.add_column("Nazwa", style="bold")
        table.add_column("MAC", style="magenta", no_wrap=True)
        table.add_column("RSSI (symulowane)", justify="right")
        table.add_column("Status", justify="right")
        for item in self._beacons:
            table.add_row(item.name, item.mac, f"{item.rssi} dBm", item.status)
        return table

    def _build_live_view(self, elapsed_sec: int):
        header = Panel(
            "\n".join(
                [
                    f"Aktywne symulacje: {sum(1 for item in self._beacons if item.status == 'ACTIVE')}",
                    f"Urządzenia łącznie: {len(self._beacons)}",
                    f"Czas działania: {elapsed_sec}s",
                    f"Interfejs: {self.interface}",
                ]
            ),
            title="BluetoothPoet Status",
            border_style="cyan",
        )
        return Group(header, self._build_device_table())

    def _render_summary(self, elapsed_sec: int) -> None:
        sample_names = [item.name for item in self._beacons[:5]]
        lines = [
            f"Status: {self.status}",
            f"Czas: {elapsed_sec}s",
            f"Urządzenia wygenerowane: {len(self._beacons)}",
            "Przykładowe nazwy:",
            *[f"- {name}" for name in sample_names],
        ]
        if self._error:
            lines.append(f"Błąd: {self._error}")
        self.console.print(
            Panel("\n".join(lines), title="Podsumowanie BluetoothPoet", border_style="green")
        )

    def _emit_webui_result(self, *, running: bool, elapsed_sec: int) -> None:
        if os.environ.get("SWISSKNIFE_WEBUI_TASK") != "1":
            return
        payload = {
            "kind": "bluetooth_poet",
            "running": bool(running),
            "timestamp": int(time.time()),
            "interface": self.interface,
            "duration": int(elapsed_sec),
            "device_count": len(self._beacons),
            "active_count": sum(1 for item in self._beacons if item.status == "ACTIVE"),
            "identity_name": self._beacons[0].name if self._beacons else "BluetoothPoet",
            "devices": [
                {
                    "name": item.name,
                    "mac": item.mac,
                    "rssi": item.rssi,
                    "status": item.status,
                }
                for item in self._beacons
            ],
            "status": self.status,
            "error": self._error,
            "disclaimer": "Laboratory BLE advertising only. Use in controlled environment.",
        }
        print(f"[webui-result] {json.dumps(payload, ensure_ascii=False)}", flush=True)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SwissKnife BluetoothPoet laboratory advertiser")
    parser.add_argument("--interface", default="hci0", help="Bluetooth interface (e.g., hci0).")
    parser.add_argument("--count", type=int, default=24, help="Number of 'devices' to cycle through (20-30).")
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Duration in seconds. Use 0 for unlimited (until Ctrl+C).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Alias for --duration (kept for WebUI compatibility).",
    )
    parser.add_argument("--refresh", type=float, default=1.0, help="Live refresh interval in seconds.")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible MACs.")
    parser.add_argument(
        "--mac-prefix",
        default="00:00:00",
        help="Prefix for generated MAC addresses (default: 00:00:00).",
    )
    parser.add_argument(
        "--advertise-interval",
        type=float,
        default=0.5,
        help="Time to advertise each name/MAC (seconds).",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    effective_duration = args.timeout if args.timeout is not None else args.duration
    module = BluetoothPoet(
        interface=args.interface,
        count=args.count,
        duration=effective_duration,
        refresh_interval=args.refresh,
        seed=args.seed,
        mac_prefix=args.mac_prefix,
        advertise_interval=args.advertise_interval,
    )
    module.run()

if __name__ == "__main__":
    main()