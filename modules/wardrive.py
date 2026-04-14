#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import glob
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from core.wifi_iface import (
        get_interface_chipset as core_get_interface_chipset,
        get_interface_mode as core_get_interface_mode,
        list_wireless_interfaces as core_list_wireless_interfaces,
        set_interface_mode as core_set_interface_mode,
    )
except ModuleNotFoundError:
    MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(MODULE_DIR)
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    from core.wifi_iface import (
        get_interface_chipset as core_get_interface_chipset,
        get_interface_mode as core_get_interface_mode,
        list_wireless_interfaces as core_list_wireless_interfaces,
        set_interface_mode as core_set_interface_mode,
    )

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
LOG_DIR = os.path.join(PROJECT_ROOT, "log")

DEFAULT_SCAN_DURATION = 8
DEFAULT_GPS_PROBE_SECONDS = 2.0
DEFAULT_GPS_ACCURACY_METERS = 5.0
NMEA_READ_CHUNK = 4096

GPS_KEYWORDS = (
    "gps",
    "gnss",
    "ublox",
    "u-blox",
    "garmin",
    "navilock",
    "global sat",
)

WIGLE_HEADER = (
    "WigleWifi-1.4,"
    "appRelease=SwissKnife,"
    "model=Linux,"
    "release=1,"
    "device=SwissKnife,"
    "display=SwissKnife,"
    "board=SwissKnife,"
    "brand=SwissKnife"
)
WIGLE_COLUMNS = [
    "MAC",
    "SSID",
    "AuthMode",
    "FirstSeen",
    "Channel",
    "RSSI",
    "CurrentLatitude",
    "CurrentLongitude",
    "AltitudeMeters",
    "AccuracyMeters",
    "Type",
]


@dataclass
class GPSFix:
    latitude: float
    longitude: float
    altitude: float
    accuracy: float
    source_sentence: str


@dataclass
class WiFiNetwork:
    bssid: str
    ssid: str
    channel: Optional[int]
    signal: Optional[float]
    encryption: str


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


def list_wireless_interfaces() -> List[str]:
    return core_list_wireless_interfaces()


def get_interface_chipset(interface: str) -> str:
    return core_get_interface_chipset(interface)


def get_interface_mode(interface: str) -> str:
    mode = core_get_interface_mode(interface, fallback_iwconfig=True, infer_monitor_suffix=True)
    return mode or "unknown"


def set_interface_mode(interface: str, mode: str) -> bool:
    ok, error = core_set_interface_mode(
        interface,
        mode,
        timeout_seconds=7.0,
        monitor_settle_seconds=2.0,
        managed_settle_seconds=1.0,
        enable_otherbss=(mode == "monitor"),
        fallback_iwconfig=True,
        infer_monitor_suffix=True,
    )
    if ok:
        return True
    logging.error("Failed to set %s mode on %s: %s", mode, interface, error or "unknown error")
    return False


def select_interface(interfaces: List[str]) -> str:
    if not interfaces:
        logging.error("No wireless interfaces found.")
        sys.exit(1)

    logging.info(style("Available wireless interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        mode = get_interface_mode(name)
        label = f"{index}) {name} -"
        logging.info("  %s %s [%s]", color_text(label, COLOR_HIGHLIGHT), chipset, mode)

    while True:
        choice = input(f"{style('Select interface', STYLE_BOLD)} (number or name): ").strip()
        if not choice:
            logging.warning("Please select an interface.")
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
        if choice in interfaces:
            return choice
        logging.warning("Invalid selection.")


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


def freq_to_channel(freq: float) -> Optional[int]:
    if 2412 <= freq <= 2472:
        return int((freq - 2407) / 5)
    if int(freq) == 2484:
        return 14
    if 5000 <= freq <= 5900:
        return int((freq - 5000) / 5)
    return None


def parse_channel_value(text: str) -> Optional[int]:
    try:
        value = int(text)
    except ValueError:
        return None
    if 1 <= value <= 196:
        return value
    return None


def parse_freq_value(text: str) -> Optional[float]:
    try:
        return float(text)
    except ValueError:
        return None


def finalize_encryption(privacy: bool, wpa: bool, wpa2: bool, wps: bool) -> str:
    if wpa2:
        encryption = "WPA2"
    elif wpa:
        encryption = "WPA"
    elif privacy:
        encryption = "WEP"
    else:
        encryption = "OPEN"
    if encryption != "WEP" and wps:
        encryption = f"{encryption}/WPS"
    return encryption


def scan_networks_once(interface: str, timeout_seconds: float = 10.0) -> List[WiFiNetwork]:
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return []
    except FileNotFoundError:
        logging.error("Required tool 'iw' not found.")
        return []

    if result.returncode != 0:
        return []

    best: Dict[str, WiFiNetwork] = {}

    current_bssid: Optional[str] = None
    current_ssid: Optional[str] = None
    current_signal: Optional[float] = None
    current_channel: Optional[int] = None
    privacy = False
    wpa = False
    wpa2 = False
    wps = False

    def flush_current() -> None:
        nonlocal current_bssid, current_ssid, current_signal, current_channel
        nonlocal privacy, wpa, wpa2, wps

        if not current_bssid:
            return

        encryption = finalize_encryption(privacy, wpa, wpa2, wps)
        network = WiFiNetwork(
            bssid=current_bssid,
            ssid=current_ssid or "<hidden>",
            channel=current_channel,
            signal=current_signal,
            encryption=encryption,
        )
        previous = best.get(network.bssid)
        if previous is None:
            best[network.bssid] = network
        else:
            prev_signal = previous.signal if previous.signal is not None else -999.0
            new_signal = network.signal if network.signal is not None else -999.0
            if new_signal > prev_signal:
                best[network.bssid] = network

        current_bssid = None
        current_ssid = None
        current_signal = None
        current_channel = None
        privacy = False
        wpa = False
        wpa2 = False
        wps = False

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("BSS "):
            flush_current()
            current_bssid = line.split()[1].split("(")[0].strip().lower()
            continue
        if line.startswith("freq:"):
            parts = line.split()
            freq = parse_freq_value(parts[1]) if len(parts) > 1 else None
            if freq is not None:
                current_channel = freq_to_channel(freq)
            continue
        if line.startswith("DS Parameter set:"):
            parts = line.split()
            if len(parts) >= 4 and parts[-2] == "channel":
                value = parse_channel_value(parts[-1])
                if value is not None:
                    current_channel = value
            continue
        if line.startswith("* primary channel:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                value = parse_channel_value(parts[1].strip())
                if value is not None:
                    current_channel = value
            continue
        if line.startswith("signal:"):
            parts = line.split()
            try:
                current_signal = float(parts[1])
            except (IndexError, ValueError):
                current_signal = None
            continue
        if line.startswith("capability:") and "Privacy" in line:
            privacy = True
            continue
        if line.startswith("RSN:"):
            wpa2 = True
            continue
        if line.startswith("WPA:"):
            wpa = True
            continue
        if "WPS" in line:
            wps = True
            continue
        if line.startswith("SSID:"):
            ssid_value = line.split(":", 1)[1].strip()
            current_ssid = ssid_value if ssid_value else "<hidden>"
            continue

    flush_current()

    return sorted(
        best.values(),
        key=lambda item: item.signal if item.signal is not None else -1000.0,
        reverse=True,
    )


def scan_networks_window(interface: str, duration_seconds: int) -> List[WiFiNetwork]:
    end_time = time.time() + max(1, duration_seconds)
    merged: Dict[str, WiFiNetwork] = {}

    while time.time() < end_time:
        chunk = scan_networks_once(interface, timeout_seconds=7.0)
        for item in chunk:
            previous = merged.get(item.bssid)
            if previous is None:
                merged[item.bssid] = item
                continue
            prev_signal = previous.signal if previous.signal is not None else -999.0
            new_signal = item.signal if item.signal is not None else -999.0
            if new_signal > prev_signal:
                merged[item.bssid] = item
            elif previous.ssid == "<hidden>" and item.ssid != "<hidden>":
                previous.ssid = item.ssid
            elif previous.channel is None and item.channel is not None:
                previous.channel = item.channel

        time.sleep(0.2)

    return sorted(
        merged.values(),
        key=lambda item: item.signal if item.signal is not None else -1000.0,
        reverse=True,
    )


def lsusb_lines() -> List[str]:
    if not tool_exists("lsusb"):
        return []
    result = subprocess.run(
        ["lsusb"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def usb_gps_matches(lines: List[str]) -> List[str]:
    matches: List[str] = []
    for line in lines:
        low = line.lower()
        if any(keyword in low for keyword in GPS_KEYWORDS):
            matches.append(line)
    return matches


def serial_device_candidates() -> List[str]:
    patterns = [
        "/dev/ttyUSB*",
        "/dev/ttyACM*",
    ]
    devices: List[str] = []
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if path not in devices:
                devices.append(path)

    by_id_paths = sorted(glob.glob("/dev/serial/by-id/*"))
    for link in by_id_paths:
        try:
            resolved = os.path.realpath(link)
        except OSError:
            continue
        if resolved and resolved.startswith("/dev/") and os.path.exists(resolved):
            if resolved not in devices:
                devices.append(resolved)

    prioritized = sorted(
        devices,
        key=lambda dev: (
            0
            if any(keyword in dev.lower() for keyword in ("gps", "gnss", "ublox", "u-blox", "garmin"))
            else 1,
            dev,
        ),
    )
    return prioritized


def configure_serial_device(device: str, baud: int) -> None:
    subprocess.run(
        [
            "stty",
            "-F",
            device,
            str(baud),
            "cs8",
            "-cstopb",
            "-parenb",
            "-icanon",
            "min",
            "1",
            "time",
            "1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def read_nmea_lines(device: str, listen_seconds: float) -> List[str]:
    lines: List[str] = []
    buffer = b""
    try:
        fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return []

    end_time = time.time() + max(0.5, listen_seconds)
    try:
        while time.time() < end_time:
            try:
                chunk = os.read(fd, NMEA_READ_CHUNK)
            except BlockingIOError:
                chunk = b""
            except OSError:
                break

            if not chunk:
                time.sleep(0.05)
                continue

            buffer += chunk
            while b"\n" in buffer:
                raw_line, buffer = buffer.split(b"\n", 1)
                text = raw_line.decode("ascii", errors="ignore").strip()
                if text.startswith("$"):
                    lines.append(text)
                if len(lines) >= 300:
                    return lines
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    return lines


def nmea_coord_to_decimal(raw_value: str, hemisphere: str, is_longitude: bool) -> Optional[float]:
    raw = (raw_value or "").strip()
    if not raw:
        return None

    degree_width = 3 if is_longitude else 2
    if len(raw) < degree_width + 2:
        return None

    try:
        degrees = int(raw[:degree_width])
        minutes = float(raw[degree_width:])
    except ValueError:
        return None

    decimal = degrees + (minutes / 60.0)

    hemi = (hemisphere or "").upper()
    if hemi in {"S", "W"}:
        decimal *= -1.0
    return decimal


def parse_gga_sentence(sentence: str) -> Optional[GPSFix]:
    parts = sentence.split(",")
    if len(parts) < 10:
        return None

    try:
        fix_quality = int(parts[6] or "0")
    except ValueError:
        fix_quality = 0
    if fix_quality <= 0:
        return None

    latitude = nmea_coord_to_decimal(parts[2], parts[3], is_longitude=False)
    longitude = nmea_coord_to_decimal(parts[4], parts[5], is_longitude=True)
    if latitude is None or longitude is None:
        return None

    try:
        altitude = float(parts[9] or "0")
    except ValueError:
        altitude = 0.0

    try:
        hdop = float(parts[8] or "")
        accuracy = max(0.5, hdop * 5.0)
    except ValueError:
        accuracy = DEFAULT_GPS_ACCURACY_METERS

    return GPSFix(
        latitude=latitude,
        longitude=longitude,
        altitude=altitude,
        accuracy=accuracy,
        source_sentence=parts[0],
    )


def parse_rmc_sentence(sentence: str) -> Optional[GPSFix]:
    parts = sentence.split(",")
    if len(parts) < 7:
        return None

    status = (parts[2] or "").upper()
    if status != "A":
        return None

    latitude = nmea_coord_to_decimal(parts[3], parts[4], is_longitude=False)
    longitude = nmea_coord_to_decimal(parts[5], parts[6], is_longitude=True)
    if latitude is None or longitude is None:
        return None

    return GPSFix(
        latitude=latitude,
        longitude=longitude,
        altitude=0.0,
        accuracy=DEFAULT_GPS_ACCURACY_METERS,
        source_sentence=parts[0],
    )


def extract_fix_from_nmea(lines: List[str]) -> Optional[GPSFix]:
    best: Optional[GPSFix] = None
    fallback: Optional[GPSFix] = None

    for line in lines:
        if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
            fix = parse_gga_sentence(line)
            if fix is not None:
                best = fix
        elif line.startswith("$GPRMC") or line.startswith("$GNRMC"):
            fix = parse_rmc_sentence(line)
            if fix is not None:
                fallback = fix

    return best or fallback


def probe_gps_device(device: str) -> Tuple[Optional[GPSFix], int]:
    sample_rates = [9600, 4800, 38400, 115200]
    total_lines = 0
    for baud in sample_rates:
        configure_serial_device(device, baud)
        lines = read_nmea_lines(device, listen_seconds=DEFAULT_GPS_PROBE_SECONDS)
        total_lines += len(lines)
        if not lines:
            continue
        fix = extract_fix_from_nmea(lines)
        if fix is not None:
            return fix, total_lines
    return None, total_lines


def detect_gps(verbose: bool = True) -> Tuple[Optional[str], Optional[GPSFix]]:
    usb_lines = lsusb_lines()
    gps_usb = usb_gps_matches(usb_lines)
    serial_devices = serial_device_candidates()

    if verbose:
        logging.info(style("GPS setup check:", STYLE_BOLD))
        if gps_usb:
            logging.info(color_text("USB GPS-like devices detected:", COLOR_SUCCESS))
            for line in gps_usb:
                logging.info("  - %s", line)
        else:
            logging.info(color_text("No explicit GPS signature in lsusb output.", COLOR_WARNING))

        if serial_devices:
            logging.info(color_text("Serial candidates:", COLOR_SUCCESS))
            for path in serial_devices:
                logging.info("  - %s", path)
        else:
            logging.info(color_text("No /dev/ttyUSB* or /dev/ttyACM* candidates found.", COLOR_WARNING))

    for device in serial_devices:
        if verbose:
            logging.info("")
            logging.info("Checking %s for NMEA + FIX...", style(device, COLOR_HIGHLIGHT, STYLE_BOLD))
        fix, nmea_lines = probe_gps_device(device)
        if fix is not None:
            if verbose:
                logging.info(
                    color_text(
                        (
                            f"GPS FIX OK on {device} | lat={fix.latitude:.6f} "
                            f"lon={fix.longitude:.6f} alt={fix.altitude:.1f}m"
                        ),
                        COLOR_SUCCESS,
                    )
                )
            return device, fix

        if verbose:
            logging.info(
                color_text(
                    f"No valid fix on {device} (NMEA lines read: {nmea_lines}).",
                    COLOR_WARNING,
                )
            )

    if verbose:
        logging.info("")
        logging.info(color_text("GPS dongle not ready: no active FIX detected.", COLOR_ERROR))
    return None, None


def next_wardrive_log_path(log_dir: str) -> str:
    os.makedirs(log_dir, exist_ok=True)
    index = 1
    while True:
        candidate = os.path.join(log_dir, f"wardrive_{index}.log")
        if not os.path.exists(candidate):
            return candidate
        index += 1


def create_wigle_log(path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(WIGLE_HEADER + "\n")
        writer = csv.writer(handle)
        writer.writerow(WIGLE_COLUMNS)


def wigle_auth_mode(encryption: str) -> str:
    text = (encryption or "").upper()
    if "WPA3" in text:
        return "[WPA3-PSK-CCMP][ESS]"
    if "WPA2" in text:
        return "[WPA2-PSK-CCMP][ESS]"
    if "WPA" in text:
        return "[WPA-PSK-CCMP][ESS]"
    if "WEP" in text:
        return "[WEP][ESS]"
    return "[ESS]"


def append_wigle_rows(path: str, networks: List[WiFiNetwork], fix: GPSFix, first_seen: str) -> int:
    if not networks:
        return 0

    rows_written = 0
    with open(path, "a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        for network in networks:
            ssid = "" if network.ssid == "<hidden>" else network.ssid
            rssi = ""
            if network.signal is not None:
                rssi = f"{network.signal:.1f}"

            channel_text = str(network.channel) if network.channel is not None else ""
            writer.writerow(
                [
                    network.bssid,
                    ssid,
                    wigle_auth_mode(network.encryption),
                    first_seen,
                    channel_text,
                    rssi,
                    f"{fix.latitude:.7f}",
                    f"{fix.longitude:.7f}",
                    f"{fix.altitude:.2f}",
                    f"{fix.accuracy:.2f}",
                    "WIFI",
                ]
            )
            rows_written += 1
    return rows_written


def install_stop_listener(stop_event: threading.Event) -> threading.Thread:
    def _waiter() -> None:
        try:
            input()
        except EOFError:
            pass
        stop_event.set()

    thread = threading.Thread(target=_waiter, daemon=True)
    thread.start()
    return thread


def run_gps_setup() -> int:
    logging.info(color_text("Wardrive GPS Setup", COLOR_HEADER))
    logging.info("Checks USB GPS dongle presence and active fix state.")
    logging.info("")

    device, fix = detect_gps(verbose=True)
    if device and fix:
        return 0
    return 1


def run_wardrive() -> int:
    logging.info(color_text("Wardrive", COLOR_HEADER))
    logging.info("Wi-Fi survey + GPS capture (Wigle log format)")
    logging.info("")

    required_tools = ["iw", "ip", "ethtool", "lsusb", "stty"]
    missing = [tool for tool in required_tools if not tool_exists(tool)]
    if missing:
        logging.error("Missing required tools: %s", ", ".join(missing))
        return 1

    interfaces = list_wireless_interfaces()
    interface = select_interface(interfaces)

    original_mode = get_interface_mode(interface)
    changed_to_managed = False

    try:
        if original_mode != "managed":
            logging.info("")
            input(
                f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to switch "
                f"{interface} to managed mode for wardriving..."
            )
            if not set_interface_mode(interface, "managed"):
                return 1
            changed_to_managed = True
            logging.info(color_text("Managed mode confirmed.", COLOR_SUCCESS))

        logging.info("")
        scan_seconds = prompt_int(
            f"{style('Scan window', STYLE_BOLD)} in seconds "
            f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} for {DEFAULT_SCAN_DURATION}): ",
            default=DEFAULT_SCAN_DURATION,
            minimum=1,
        )

        gps_device = None
        gps_fix = None
        while True:
            logging.info("")
            input(
                f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to run GPS setup before wardrive..."
            )
            gps_device, gps_fix = detect_gps(verbose=True)
            if gps_device and gps_fix:
                break

            choice = input(
                f"{style('Retry GPS setup', STYLE_BOLD)} (R) or {style('Exit', STYLE_BOLD)} (E): "
            ).strip().lower()
            if choice != "r":
                return 1

        log_path = next_wardrive_log_path(LOG_DIR)
        create_wigle_log(log_path)

        logging.info("")
        logging.info(color_text(f"Wigle log file: {log_path}", COLOR_SUCCESS))
        logging.info(
            "Press %s to stop wardriving.",
            style("Enter (or Ctrl+C)", COLOR_SUCCESS, STYLE_BOLD),
        )

        stop_event = threading.Event()
        stopper = install_stop_listener(stop_event)

        cycle = 0
        total_rows = 0
        last_fix = gps_fix

        while not stop_event.is_set():
            cycle += 1

            fresh_fix, _line_count = probe_gps_device(gps_device)
            if fresh_fix is not None:
                last_fix = fresh_fix

            if last_fix is None:
                logging.warning("[%s] GPS fix unavailable, skipping this cycle.", cycle)
                time.sleep(0.6)
                continue

            networks = scan_networks_window(interface, scan_seconds)
            if not networks:
                logging.warning("[%s] No Wi-Fi networks captured in this scan window.", cycle)
                continue

            first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            written = append_wigle_rows(log_path, networks, last_fix, first_seen)
            total_rows += written

            logging.info(
                color_text(
                    (
                        f"[{cycle}] rows={written} total={total_rows} "
                        f"lat={last_fix.latitude:.6f} lon={last_fix.longitude:.6f}"
                    ),
                    COLOR_HIGHLIGHT,
                )
            )

        if stopper.is_alive():
            stopper.join(timeout=0.2)

        logging.info("")
        logging.info(style("Wardrive summary:", STYLE_BOLD))
        logging.info("  Interface: %s", interface)
        logging.info("  GPS device: %s", gps_device)
        logging.info("  Rows written: %s", total_rows)
        logging.info("  Log file: %s", log_path)

    except KeyboardInterrupt:
        logging.info("")
        logging.info(color_text("Wardrive interrupted by user.", COLOR_WARNING))
    finally:
        if changed_to_managed and original_mode == "monitor":
            logging.info("Restoring monitor mode...")
            set_interface_mode(interface, "monitor")

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SwissKnife Wardrive module")
    parser.add_argument("--gps-setup", action="store_true", help="Run USB GPS setup/fix check and exit")
    parser.add_argument("--start", action="store_true", help="Start wardriving session")
    return parser.parse_args()


def main() -> None:
    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    args = parse_args()

    if args.gps_setup:
        code = run_gps_setup()
        sys.exit(code)

    code = run_wardrive()
    sys.exit(code)


if __name__ == "__main__":
    main()
