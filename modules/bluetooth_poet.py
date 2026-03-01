#!/usr/bin/env python3

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
    from rich import box
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:
    class Console:  # type: ignore[override]
        def print(self, *objects: object, **_kwargs: object) -> None:
            print(*objects)

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

    class Group:  # type: ignore[override]
        def __init__(self, *objects: object) -> None:
            self.objects = objects

        def __str__(self) -> str:
            return "\n\n".join(str(item) for item in self.objects)

    class Live:  # type: ignore[override]
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


try:
    import dbus
    import dbus.exceptions
    import dbus.mainloop.glib
    import dbus.service

    DBUS_AVAILABLE = True
except Exception:
    DBUS_AVAILABLE = False
    dbus = None  # type: ignore[assignment]


BLUEZ_SERVICE_NAME = "org.bluez"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"
LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"

MIN_BEACONS = 20
MAX_BEACONS = 30

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
""".strip()


if DBUS_AVAILABLE:
    class InvalidArgsException(dbus.exceptions.DBusException):
        _dbus_error_name = "org.freedesktop.DBus.Error.InvalidArgs"


    class Advertisement(dbus.service.Object):
        PATH_BASE = "/org/bluez/example/advertisement"

        def __init__(self, bus, index: int, advertising_type: str, local_name: str):
            self.path = self.PATH_BASE + str(index)
            self.bus = bus
            self.ad_type = advertising_type
            self.local_name = local_name
            self.include_tx_power = True
            dbus.service.Object.__init__(self, bus, self.path)

        def get_properties(self):
            properties = {
                "Type": self.ad_type,
                "LocalName": dbus.String(self.local_name),
            }
            if self.include_tx_power:
                properties["Includes"] = dbus.Array(["tx-power"], signature="s")
            return {LE_ADVERTISEMENT_IFACE: properties}

        def get_path(self):
            return dbus.ObjectPath(self.path)

        @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
        def GetAll(self, interface):
            if interface != LE_ADVERTISEMENT_IFACE:
                raise InvalidArgsException()
            return self.get_properties()[LE_ADVERTISEMENT_IFACE]

        @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature="", out_signature="")
        def Release(self):
            pass

else:
    class Advertisement:  # type: ignore[override]
        def __init__(self, *args, **kwargs):
            raise RuntimeError("dbus-python is not available")


@dataclass
class BeaconEntry:
    name: str
    mac: str
    rssi: int
    status: str = "ACTIVE"


def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def clean_poem_lines(text: str) -> List[str]:
    lines: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line:
            lines.append(line)
    return lines


def sanitize_display_name(line: str, max_len: int = 26) -> str:
    clean = " ".join((line or "").split())
    if not clean:
        return "BluetoothPoet"
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 1].rstrip() + "…"


class BluetoothPoet(Module):
    def __init__(
        self,
        *,
        interface: str = "hci0",
        count: int = 24,
        duration: int = 60,
        refresh_interval: float = 1.0,
        seed: Optional[int] = None,
        mac_prefix: str = "00:00:00",
        advertise_interval: float = 0.5,
        name_mode: str = "cycle",
    ) -> None:
        super().__init__(name="BluetoothPoet")
        self.interface = (interface or "hci0").strip()
        self.count = clamp(int(count), MIN_BEACONS, MAX_BEACONS)
        self.duration = max(0, int(duration))
        self.refresh_interval = max(0.2, float(refresh_interval))
        self.seed = seed
        self.mac_prefix = mac_prefix.strip() or "00:00:00"
        self.advertise_interval = max(0.1, float(advertise_interval))
        self.name_mode = (name_mode or "cycle").strip().lower()

        self.running = False
        self.status = "idle"
        self._stop_event = threading.Event()
        self._signal_handlers: Dict[int, object] = {}
        self._error: Optional[str] = None

        self._beacons: List[BeaconEntry] = []
        self._poem_lines = clean_poem_lines(PAN_TADEUSZ_INWOKACJA)

        self.bus = None
        self.ad_manager = None
        self.current_ad: Optional[Advertisement] = None
        self._rotation_index = 0

    def run(self) -> None:
        started = time.time()
        self.running = True
        self.status = "running"
        self._stop_event.clear()
        self._install_signal_handlers()

        self.console.print(
            Panel.fit(
                "BluetoothPoet (tryb laboratoryjny)\n"
                "Realne nadawanie beaconów BLE w kontrolowanym środowisku.",
                border_style="cyan",
                title="SwissKnife",
            )
        )
        self.console.print(
            "[yellow]Używaj wyłącznie w kontrolowanym laboratorium na własnych urządzeniach.[/yellow]"
        )

        try:
            self._ensure_runtime_requirements()
            self._initialize_bluez()
            self._beacons = self._build_beacons()

            self.console.print(
                "[bold cyan]Nadawanie beaconów BLE z wierszem Mickiewicza w toku "
                "(tryb laboratoryjny) — Ctrl+C aby zatrzymać[/bold cyan]"
            )

            with Live(
                self._build_live_view(0),
                console=self.console,
                refresh_per_second=max(2, int(1.0 / self.refresh_interval) + 1),
                transient=False,
            ) as live:
                last_emit = 0.0
                while not self._stop_event.is_set():
                    elapsed = int(time.time() - started)
                    if self.duration > 0 and elapsed >= self.duration:
                        break

                    self._advertise_next_beacon()
                    self._jitter_rssi()

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
            self._safe_unregister_current()
            self._mark_stopped()
            elapsed = max(0, int(time.time() - started))
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

    def _ensure_runtime_requirements(self) -> None:
        if os.geteuid() != 0:
            raise RuntimeError("BluetoothPoet requires root privileges.")
        if not DBUS_AVAILABLE:
            raise RuntimeError("Missing Python dependencies: dbus-python / pygobject")

    def _initialize_bluez(self) -> None:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self.bus = dbus.SystemBus()
        adapter = self._find_adapter(self.bus)
        if not adapter:
            raise RuntimeError("LEAdvertisingManager1 interface not found")

        adapter_props = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, adapter), DBUS_PROP_IFACE)
        adapter_props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(1))

        self.ad_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, adapter),
            LE_ADVERTISING_MANAGER_IFACE,
        )

    def _find_adapter(self, bus):
        remote_om = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, "/"), DBUS_OM_IFACE)
        objects = remote_om.GetManagedObjects()
        for path, props in objects.items():
            if LE_ADVERTISING_MANAGER_IFACE in props:
                return path
        return None

    def _change_mac(self, new_mac: str) -> None:
        subprocess.check_call(["hciconfig", self.interface, "down"])
        subprocess.check_call(["bdaddr", "-i", self.interface, new_mac])
        subprocess.check_call(["hciconfig", self.interface, "up"])

    def _safe_unregister_current(self) -> None:
        if not self.current_ad or not self.ad_manager:
            return
        try:
            self.ad_manager.UnregisterAdvertisement(self.current_ad.get_path())
        except Exception:
            pass
        try:
            dbus.service.Object.remove_from_connection(self.current_ad)
        except Exception:
            pass
        self.current_ad = None

    def _build_beacons(self) -> List[BeaconEntry]:
        if not self._poem_lines:
            raise RuntimeError("Brak linijek tekstu do BluetoothPoet.")

        rng = random.Random(self.seed)
        names = [sanitize_display_name(line) for line in self._poem_lines]
        if self.name_mode == "random":
            picked_names = [rng.choice(names) for _ in range(self.count)]
        else:
            picked_names = [names[index % len(names)] for index in range(self.count)]

        beacons: List[BeaconEntry] = []
        for index in range(self.count):
            beacons.append(
                BeaconEntry(
                    name=picked_names[index],
                    mac=self._make_mac(index, rng),
                    rssi=rng.randint(-88, -42),
                    status="ACTIVE",
                )
            )
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

        suffix = [
            (index >> 16) & 0xFF,
            (index >> 8) & 0xFF,
            ((index & 0xFF) ^ rng.randint(0, 255)) & 0xFF,
        ]
        octets = prefix_octets + suffix
        return ":".join(f"{value:02X}" for value in octets)

    def _advertise_next_beacon(self) -> None:
        if not self._beacons:
            return

        beacon = self._beacons[self._rotation_index % len(self._beacons)]

        try:
            self._change_mac(beacon.mac)
        except Exception as exc:
            self.console.print(
                f"[yellow]Nie udało się zmienić MAC ({beacon.mac}): {exc}. Kontynuuję.[/yellow]"
            )

        self._safe_unregister_current()
        self.current_ad = Advertisement(
            self.bus,
            self._rotation_index,
            "peripheral",
            beacon.name,
        )

        self.ad_manager.RegisterAdvertisement(self.current_ad.get_path(), {})
        self._sleep_interruptible(self.advertise_interval)
        self._safe_unregister_current()

        self._rotation_index += 1

    def _jitter_rssi(self) -> None:
        rng = random.Random()
        for item in self._beacons:
            item.rssi = clamp(item.rssi + rng.randint(-2, 2), -95, -35)

    def _mark_stopped(self) -> None:
        for item in self._beacons:
            item.status = "STOPPED"

    def _build_table(self) -> Table:
        table = Table(title="Nadawane beacony BLE", box=box.SIMPLE_HEAVY)
        table.add_column("Nazwa", style="bold")
        table.add_column("MAC", style="magenta", no_wrap=True)
        table.add_column("RSSI", justify="right")
        table.add_column("Status", justify="right")

        for item in self._beacons:
            table.add_row(item.name, item.mac, f"{item.rssi} dBm", item.status)
        return table

    def _build_live_view(self, elapsed_sec: int):
        panel = Panel(
            "\n".join(
                [
                    f"Aktywne symulacje: {sum(1 for item in self._beacons if item.status == 'ACTIVE')}",
                    f"Urządzenia łącznie: {len(self._beacons)}",
                    f"Interfejs: {self.interface}",
                    f"Czas działania: {elapsed_sec}s",
                    f"Tryb nazw: {self.name_mode}",
                ]
            ),
            title="BluetoothPoet Status",
            border_style="cyan",
        )
        return Group(panel, self._build_table())

    def _render_summary(self, elapsed_sec: int) -> None:
        sample_names = [item.name for item in self._beacons[:5]]
        lines = [
            f"Status: {self.status}",
            f"Czas: {elapsed_sec}s",
            f"Urządzenia przygotowane: {len(self._beacons)}",
            f"Interfejs: {self.interface}",
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
    parser.add_argument("--interface", default="hci0", help="Bluetooth interface (e.g. hci0).")
    parser.add_argument("--count", type=int, default=24, help="Number of rotating beacon profiles (20-30).")
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
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible profiles.")
    parser.add_argument(
        "--mac-prefix",
        default="00:00:00",
        help="Prefix for generated MAC addresses (default: 00:00:00).",
    )
    parser.add_argument(
        "--advertise-interval",
        type=float,
        default=0.5,
        help="Time to advertise each profile before switching.",
    )
    parser.add_argument(
        "--name-mode",
        choices=["cycle", "random"],
        default="cycle",
        help="How poem lines are assigned to beacon profiles.",
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
        name_mode=args.name_mode,
    )
    module.run()


if __name__ == "__main__":
    main()
