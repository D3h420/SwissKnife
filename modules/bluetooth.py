#!/usr/bin/env python3

import os
import re
import sys
import time
import subprocess
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

DEFAULT_SCAN_SECONDS = 12
DEFAULT_SPAM_SECONDS = 30
DEFAULT_SPAM_INTERVAL = 1.2
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

DEVICE_EVENT_PATTERN = re.compile(r"Device\s+([0-9A-Fa-f:]{17})(?:\s+(.*))?$")
DEVICE_LIST_PATTERN = re.compile(r"Device\s+([0-9A-Fa-f:]{17})\s+(.+)$")
RSSI_PATTERN = re.compile(r"RSSI:\s*(-?\d+)")


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


@dataclass
class BluetoothDevice:
    mac: str
    name: str = "<unknown>"
    rssi: Optional[int] = None


def prompt_int(prompt: str, default: int, minimum: int = 1) -> int:
    raw = input(prompt).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    return value


def prompt_float(prompt: str, default: float, minimum: float = 0.2) -> float:
    raw = input(prompt).strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    return value


def run_bluetoothctl(args: List[str], capture_output: bool = False) -> subprocess.CompletedProcess:
    kwargs = {"text": True, "check": False}
    if capture_output:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    else:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    return subprocess.run(["bluetoothctl", *args], **kwargs)


def ensure_bluetooth_service() -> None:
    if subprocess.run(["which", "systemctl"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        return
    status = subprocess.run(
        ["systemctl", "is-active", "bluetooth"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if status.stdout.strip() == "active":
        return
    subprocess.run(
        ["systemctl", "start", "bluetooth"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def extract_device_event(devices: Dict[str, BluetoothDevice], line: str) -> None:
    match = DEVICE_EVENT_PATTERN.search(line)
    if not match:
        return

    mac = match.group(1).upper()
    payload = (match.group(2) or "").strip()
    device = devices.get(mac)
    if device is None:
        device = BluetoothDevice(mac=mac)
        devices[mac] = device

    rssi_match = RSSI_PATTERN.search(payload)
    if rssi_match:
        try:
            device.rssi = int(rssi_match.group(1))
        except ValueError:
            pass
        return

    if not payload:
        return
    if payload.startswith(
        (
            "Name:",
            "Alias:",
            "TxPower:",
            "ManufacturerData",
            "ServiceData",
            "UUID",
            "Class",
            "Address Type",
            "ServicesResolved",
        )
    ):
        if payload.startswith(("Name:", "Alias:")):
            _, value = payload.split(":", 1)
            cleaned = value.strip()
            if cleaned:
                device.name = cleaned
        return

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
        if mac not in devices:
            devices[mac] = BluetoothDevice(mac=mac, name=name)
            continue
        if devices[mac].name in ("", "<unknown>"):
            devices[mac].name = name


def scan_bt_devices(duration_seconds: int) -> List[BluetoothDevice]:
    ensure_bluetooth_service()
    result = run_bluetoothctl(["--timeout", str(duration_seconds), "scan", "on"], capture_output=True)

    devices: Dict[str, BluetoothDevice] = {}
    for raw_line in (result.stdout + "\n" + result.stderr).splitlines():
        extract_device_event(devices, raw_line.strip())

    merge_known_devices(devices)

    sorted_devices = sorted(
        devices.values(),
        key=lambda item: (item.rssi is None, -(item.rssi if item.rssi is not None else -1000), item.name.lower()),
    )
    return sorted_devices


def get_current_alias() -> Optional[str]:
    result = run_bluetoothctl(["show"], capture_output=True)
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Alias:"):
            return line.split(":", 1)[1].strip()
    return None


def prepare_ble_spam() -> None:
    ensure_bluetooth_service()
    run_bluetoothctl(["power", "on"])
    run_bluetoothctl(["discoverable", "on"])
    run_bluetoothctl(["pairable", "on"])
    run_bluetoothctl(["agent", "NoInputNoOutput"])


def run_ble_spam(duration_seconds: int, interval_seconds: float) -> None:
    original_alias = get_current_alias()
    prepare_ble_spam()

    end_time = time.time() + duration_seconds if duration_seconds > 0 else None
    try:
        while True:
            for alias in BLE_SPAM_ALIASES:
                if end_time and time.time() >= end_time:
                    return
                run_bluetoothctl(["system-alias", alias])
                logging.info("  %s: %s", style("Broadcasting", STYLE_BOLD), color_text(alias, COLOR_HIGHLIGHT))
                time.sleep(interval_seconds)
    except KeyboardInterrupt:
        logging.info("")
        logging.info(color_text("BLE spam stopped by user.", COLOR_WARNING))
    finally:
        if original_alias:
            run_bluetoothctl(["system-alias", original_alias])


def display_scanned_devices(devices: List[BluetoothDevice]) -> None:
    logging.info("")
    if not devices:
        logging.warning("No Bluetooth devices found.")
        return

    logging.info(style("Discovered Bluetooth devices:", STYLE_BOLD))
    for index, device in enumerate(devices, start=1):
        rssi = f"rssi {device.rssi} dBm" if device.rssi is not None else "rssi ?"
        label = f"{index}) {device.name} ({device.mac}) -"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), rssi)


def scan_flow() -> None:
    logging.info("")
    duration = prompt_int(
        f"{style('Scan duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for {style(str(DEFAULT_SCAN_SECONDS), COLOR_SUCCESS, STYLE_BOLD)}): ",
        default=DEFAULT_SCAN_SECONDS,
        minimum=1,
    )
    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to start Bluetooth scan...")
    devices = scan_bt_devices(duration)
    display_scanned_devices(devices)
    input(style("Press Enter to return.", STYLE_BOLD))


def spam_flow() -> None:
    logging.info("")
    logging.info(style("Disclaimer:", STYLE_BOLD))
    logging.info("Use BLE Spam only for authorized testing on your own devices.")
    choice = input(f"{style('Proceed', STYLE_BOLD)}? (Y/N): ").strip().lower()
    if choice != "y":
        logging.info(color_text("Aborted by user.", COLOR_WARNING))
        return

    logging.info("")
    duration = prompt_int(
        f"{style('Spam duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for {style(str(DEFAULT_SPAM_SECONDS), COLOR_SUCCESS, STYLE_BOLD)}, "
        f"{style('0', STYLE_BOLD)} = until Ctrl+C): ",
        default=DEFAULT_SPAM_SECONDS,
        minimum=0,
    )
    interval = prompt_float(
        f"{style('Switch interval', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for {style(str(DEFAULT_SPAM_INTERVAL), COLOR_SUCCESS, STYLE_BOLD)}): ",
        default=DEFAULT_SPAM_INTERVAL,
        minimum=0.2,
    )

    logging.info("")
    input(
        f"{style('Press Enter', STYLE_BOLD)} to start BLE spam "
        f"({style('Ctrl+C', STYLE_BOLD)} to stop)..."
    )
    run_ble_spam(duration, interval)
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

    required_tools = ["bluetoothctl"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
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
