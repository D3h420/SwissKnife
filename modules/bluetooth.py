#!/usr/bin/env python3

import os
import re
import sys
import time
import threading
import subprocess
import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

BLE_SPAM_ALIASES = [
    "SpamJam_XOXO",
    "HAXX",
    "BLE_Boop",
    "x0x0x",
    "Free_Wifi_LOL",
    "Not_A_Trap",
    "BT_Bomb",
    "UFO-SIGNAL",
    "CandyBLE",
    "NSA_Van",
    "HackThePlanet",
    "ekomsSavior",
]
DEFAULT_SPAM_INTERVAL_SECONDS = 1.0

ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
DEVICE_EVENT_PATTERN = re.compile(r"^\[(NEW|CHG|DEL)\]\s+Device\s+([0-9A-Fa-f:]{17})(?:\s+(.*))?$")
DEVICE_LIST_PATTERN = re.compile(r"^Device\s+([0-9A-Fa-f:]{17})\s+(.+)$")
RSSI_PATTERN = re.compile(r"RSSI:\s*(-?\d+)")
HCI_INTERFACE_PATTERN = re.compile(r"^(hci\d+):")


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def tool_exists(tool: str) -> bool:
    return subprocess.run(
        ["which", tool],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def run_command(
    args: List[str],
    capture_output: bool = False,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    kwargs = {"text": True, "check": False}
    if capture_output:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    else:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    if timeout is not None:
        kwargs["timeout"] = timeout
    return subprocess.run(args, **kwargs)


def run_bluetoothctl(args: List[str], capture_output: bool = False) -> subprocess.CompletedProcess:
    return run_command(["bluetoothctl", *args], capture_output=capture_output)


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_PATTERN.sub("", text)


@dataclass
class BluetoothDevice:
    mac: str
    name: str = "<unknown>"
    rssi: Optional[int] = None
    last_seen: float = 0.0


class BluetoothctlSession:
    def __init__(self, on_line: Optional[Callable[[str], None]] = None):
        self.on_line = on_line
        self.process: Optional[subprocess.Popen] = None
        self.stop_event = threading.Event()
        self.reader_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.process = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()

    def _reader_loop(self) -> None:
        if not self.process or not self.process.stdout:
            return
        while not self.stop_event.is_set():
            line = self.process.stdout.readline()
            if line == "":
                if self.process.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            cleaned = strip_ansi(line.strip())
            if self.on_line:
                self.on_line(cleaned)

    def send(self, command: str) -> None:
        if not self.process or not self.process.stdin:
            return
        try:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
        except Exception:
            pass

    def close(self) -> None:
        self.stop_event.set()
        if self.process:
            try:
                self.send("scan off")
                self.send("quit")
            except Exception:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1)


def ensure_bluetooth_service() -> None:
    if tool_exists("rfkill"):
        run_command(["rfkill", "unblock", "bluetooth"])

    if tool_exists("systemctl"):
        active = run_command(["systemctl", "is-active", "bluetooth"], capture_output=True)
        if active.stdout.strip() != "active":
            run_command(["systemctl", "start", "bluetooth"])

    run_bluetoothctl(["power", "on"])


def ensure_controller_available() -> bool:
    result = run_bluetoothctl(["list"], capture_output=True)
    for raw_line in result.stdout.splitlines():
        if raw_line.strip().startswith("Controller "):
            return True
    return False


def update_device_from_bt_line(devices: Dict[str, BluetoothDevice], line: str) -> None:
    match = DEVICE_EVENT_PATTERN.match(line)
    if not match:
        return

    action = match.group(1)
    mac = match.group(2).upper()
    payload = (match.group(3) or "").strip()

    if action == "DEL":
        if mac in devices:
            devices[mac].last_seen = time.time()
        return

    now = time.time()
    device = devices.get(mac)
    if device is None:
        device = BluetoothDevice(mac=mac, last_seen=now)
        devices[mac] = device
    else:
        device.last_seen = now

    if not payload:
        return

    rssi_match = RSSI_PATTERN.search(payload)
    if rssi_match:
        try:
            device.rssi = int(rssi_match.group(1))
        except ValueError:
            pass
        return

    if payload.startswith(("Name:", "Alias:")):
        _, name = payload.split(":", 1)
        name = name.strip()
        if name:
            device.name = name
        return

    if payload.startswith(
        (
            "TxPower:",
            "ManufacturerData",
            "ServiceData",
            "UUID",
            "Class",
            "Address Type",
            "ServicesResolved",
            "Paired:",
            "Trusted:",
            "Blocked:",
            "Connected:",
            "LegacyPairing:",
            "RSSI:",
        )
    ):
        return

    if payload:
        device.name = payload


def merge_known_devices(devices: Dict[str, BluetoothDevice]) -> None:
    result = run_bluetoothctl(["devices"], capture_output=True)
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        match = DEVICE_LIST_PATTERN.match(line)
        if not match:
            continue
        mac = match.group(1).upper()
        name = match.group(2).strip() or "<unknown>"
        existing = devices.get(mac)
        if existing is None:
            devices[mac] = BluetoothDevice(mac=mac, name=name, last_seen=time.time())
            continue
        if existing.name in ("", "<unknown>"):
            existing.name = name


def sorted_devices(devices: Dict[str, BluetoothDevice]) -> List[BluetoothDevice]:
    return sorted(
        devices.values(),
        key=lambda item: (
            item.rssi is None,
            -(item.rssi if item.rssi is not None else -1000),
            item.name.lower(),
            item.mac,
        ),
    )


def render_scan_live(devices: Dict[str, BluetoothDevice], started_at: float) -> None:
    elapsed = int(time.time() - started_at)
    lines = [
        style("BT Scan (live)", STYLE_BOLD),
        f"Elapsed: {elapsed}s",
        f"Devices: {len(devices)}",
        "Press Enter or Ctrl+C to stop.",
        "",
    ]

    ordered = sorted_devices(devices)
    if not ordered:
        lines.append(color_text("Scanning... no devices yet.", COLOR_WARNING))
    else:
        for index, device in enumerate(ordered, start=1):
            rssi_text = f"rssi {device.rssi} dBm" if device.rssi is not None else "rssi ?"
            label = f"{index}) {device.name} ({device.mac}) -"
            lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {rssi_text}")

    output = "\n".join(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


def scan_bt_devices_live() -> List[BluetoothDevice]:
    ensure_bluetooth_service()
    if not ensure_controller_available():
        logging.error("No Bluetooth controller detected.")
        return []

    devices: Dict[str, BluetoothDevice] = {}
    lock = threading.Lock()

    def on_line(line: str) -> None:
        if not line:
            return
        with lock:
            update_device_from_bt_line(devices, line)

    session = BluetoothctlSession(on_line=on_line)
    stop_event = threading.Event()
    started_at = time.time()

    def wait_for_enter() -> None:
        try:
            input()
        except EOFError:
            pass
        stop_event.set()

    stopper = threading.Thread(target=wait_for_enter, daemon=True)
    try:
        session.start()
        session.send("power on")
        session.send("pairable on")
        session.send("discoverable on")
        session.send("scan on")
        stopper.start()

        last_merge = 0.0
        while not stop_event.is_set():
            now = time.time()
            if now - last_merge > 3.0:
                with lock:
                    merge_known_devices(devices)
                last_merge = now

            with lock:
                snapshot = {mac: BluetoothDevice(**vars(dev)) for mac, dev in devices.items()}
            render_scan_live(snapshot, started_at)
            time.sleep(0.8)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        session.close()
        stop_event.set()
        if stopper.is_alive():
            stopper.join(timeout=0.2)

    with lock:
        return sorted_devices(devices)


def list_hci_interfaces() -> List[str]:
    if not tool_exists("hciconfig"):
        return []
    result = run_command(["hciconfig"], capture_output=True)
    interfaces: List[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        match = HCI_INTERFACE_PATTERN.match(line)
        if match:
            interfaces.append(match.group(1))
    return interfaces


def select_hci_interface(interfaces: List[str]) -> str:
    if not interfaces:
        return "hci0"
    if len(interfaces) == 1:
        return interfaces[0]

    logging.info("")
    logging.info(style("Available Bluetooth interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        label = f"{index})"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), name)

    while True:
        choice = input(f"{style('Select Bluetooth interface', STYLE_BOLD)} (number): ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
        logging.warning("Invalid selection. Try again.")


def run_hcitool_cmd(interface: str, ogf: str, ocf: str, params: List[str]) -> bool:
    result = run_command(
        ["hcitool", "-i", interface, "cmd", ogf, ocf, *params],
        capture_output=True,
        timeout=4.0,
    )
    return result.returncode == 0


def setup_hci_le_advertising(interface: str) -> bool:
    if not (tool_exists("hciconfig") and tool_exists("hcitool")):
        return False

    run_command(["hciconfig", interface, "up"])
    run_command(["hciconfig", interface, "leadv", "3"])
    # Disable advertising before reconfiguration.
    run_hcitool_cmd(interface, "0x08", "0x000A", ["00"])
    # Set LE advertising parameters (connectable, general channels).
    params = [
        "A0",
        "00",
        "A0",
        "00",
        "00",
        "00",
        "00",
        "00",
        "00",
        "00",
        "00",
        "00",
        "00",
        "07",
        "00",
    ]
    return run_hcitool_cmd(interface, "0x08", "0x0006", params)


def set_hci_advertisement_name(interface: str, name: str) -> bool:
    encoded_name = name.encode("utf-8", errors="ignore")[:26]
    payload = [0x02, 0x01, 0x06, len(encoded_name) + 1, 0x09, *encoded_name]
    while len(payload) < 31:
        payload.append(0x00)

    adv_data = [f"{byte:02X}" for byte in payload]
    ok_data = run_hcitool_cmd(interface, "0x08", "0x0008", ["1F", *adv_data])
    ok_enable = run_hcitool_cmd(interface, "0x08", "0x000A", ["01"])
    return ok_data and ok_enable


def disable_hci_advertising(interface: str) -> None:
    if not tool_exists("hcitool"):
        return
    run_hcitool_cmd(interface, "0x08", "0x000A", ["00"])
    if tool_exists("hciconfig"):
        run_command(["hciconfig", interface, "noleadv"])


def get_current_alias() -> Optional[str]:
    result = run_bluetoothctl(["show"], capture_output=True)
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Alias:"):
            return line.split(":", 1)[1].strip()
    return None


def run_ble_spam(interface: str, interval_seconds: float = DEFAULT_SPAM_INTERVAL_SECONDS) -> None:
    ensure_bluetooth_service()
    if not ensure_controller_available():
        logging.error("No Bluetooth controller detected.")
        return

    run_bluetoothctl(["power", "on"])
    run_bluetoothctl(["discoverable", "on"])
    run_bluetoothctl(["pairable", "on"])
    run_bluetoothctl(["agent", "NoInputNoOutput"])
    if tool_exists("hciconfig"):
        run_command(["hciconfig", interface, "piscan"])

    original_alias = get_current_alias()
    raw_adv_ready = setup_hci_le_advertising(interface)
    if raw_adv_ready:
        logging.info("BLE advertiser backend: %s", color_text("hcitool/hciconfig", COLOR_SUCCESS))
    else:
        logging.warning("BLE advertiser backend fallback: bluetoothctl alias only.")
        logging.warning("Install bluez tools (hcitool/hciconfig) for stronger BLE visibility.")

    try:
        while True:
            for alias in BLE_SPAM_ALIASES:
                run_bluetoothctl(["system-alias", alias])
                if raw_adv_ready:
                    set_hci_advertisement_name(interface, alias)
                logging.info("  %s: %s", style("Broadcasting", STYLE_BOLD), color_text(alias, COLOR_HIGHLIGHT))
                time.sleep(interval_seconds)
    except KeyboardInterrupt:
        logging.info("")
        logging.info(color_text("BLE spam stopped by user.", COLOR_WARNING))
    finally:
        if raw_adv_ready:
            disable_hci_advertising(interface)
        if original_alias:
            run_bluetoothctl(["system-alias", original_alias])


def scan_flow() -> None:
    logging.info("")
    input(
        f"{style('Press Enter', STYLE_BOLD)} to start live BT scan "
        f"({style('Enter/Ctrl+C', STYLE_BOLD)} to stop)..."
    )
    devices = scan_bt_devices_live()
    logging.info("")
    if not devices:
        logging.warning("No Bluetooth devices found.")
    else:
        logging.info(style("Final discovered devices:", STYLE_BOLD))
        for index, device in enumerate(devices, start=1):
            rssi_text = f"rssi {device.rssi} dBm" if device.rssi is not None else "rssi ?"
            label = f"{index}) {device.name} ({device.mac}) -"
            logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), rssi_text)
    input(style("Press Enter to return.", STYLE_BOLD))


def spam_flow() -> None:
    logging.info("")
    logging.info(style("Disclaimer:", STYLE_BOLD))
    logging.info("Use BLE Spam only for authorized testing on your own devices.")
    choice = input(f"{style('Proceed', STYLE_BOLD)}? (Y/N): ").strip().lower()
    if choice != "y":
        logging.info(color_text("Aborted by user.", COLOR_WARNING))
        return

    interface = select_hci_interface(list_hci_interfaces())

    logging.info("")
    input(
        f"{style('Press Enter', STYLE_BOLD)} to start BLE spam on {interface} "
        f"({style('Ctrl+C', STYLE_BOLD)} to stop)..."
    )
    run_ble_spam(interface)
    input(style("Press Enter to return.", STYLE_BOLD))


def menu_loop() -> None:
    while True:
        logging.info("")
        logging.info(style("Bluetooth menu:", STYLE_BOLD))
        logging.info("  %s", color_text("[1] Scan BT devices", COLOR_HIGHLIGHT))
        logging.info("  %s", color_text("[2] BLE Spam", COLOR_HIGHLIGHT))
        logging.info("  %s", color_text("[3] Back", COLOR_HIGHLIGHT))
        choice = input(style("Your choice (1-3): ", STYLE_BOLD)).strip()
        if choice == "1":
            scan_flow()
            continue
        if choice == "2":
            spam_flow()
            continue
        if choice == "3":
            return
        logging.warning("Invalid choice.")


def main() -> None:
    logging.info(color_text("Bluetooth Toolkit", COLOR_HEADER))
    logging.info("Bluetooth discovery and BLE spam")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not tool_exists("bluetoothctl"):
        logging.error("Required tool 'bluetoothctl' not found!")
        sys.exit(1)

    mode = sys.argv[1].strip().lower() if len(sys.argv) > 1 else ""
    if mode == "scan":
        scan_flow()
        return
    if mode == "spam":
        spam_flow()
        return

    menu_loop()


if __name__ == "__main__":
    main()
