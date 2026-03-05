#!/usr/bin/env python3

import os
import sys
import time
import csv
import signal
import subprocess
import threading
import tempfile
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

try:
    from core.wifi_iface import (
        get_interface_chipset as core_get_interface_chipset,
        get_interface_mode as core_get_interface_mode,
        list_network_interfaces as core_list_network_interfaces,
        restore_managed_mode as core_restore_managed_mode,
        set_interface_type as core_set_interface_type,
        wait_for_monitor_settle as core_wait_for_monitor_settle,
    )
except ModuleNotFoundError:
    MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(MODULE_DIR)
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    from core.wifi_iface import (
        get_interface_chipset as core_get_interface_chipset,
        get_interface_mode as core_get_interface_mode,
        list_network_interfaces as core_list_network_interfaces,
        restore_managed_mode as core_restore_managed_mode,
        set_interface_type as core_set_interface_type,
        wait_for_monitor_settle as core_wait_for_monitor_settle,
    )

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
DEFAULT_VENDOR_DB = os.environ.get(
    "SWISSKNIFE_VENDOR_DB", os.path.join(MODULE_DIR, "oui.txt")
)
DEFAULT_MONITOR_CHANNELS = (
    list(range(1, 15))
    + [
        36,
        40,
        44,
        48,
        52,
        56,
        60,
        64,
        100,
        104,
        108,
        112,
        116,
        120,
        124,
        128,
        132,
        136,
        140,
        144,
        149,
        153,
        157,
        161,
        165,
    ]
)
DEFAULT_HOP_INTERVAL = 0.8
DEFAULT_LIVE_UPDATE_INTERVAL = 0.5
MONITOR_SETTLE_SECONDS = 2.0
SCAN_BUSY_RETRY_DELAY = 0.8
SCAN_COMMAND_TIMEOUT = 4.0
AIRODUMP_WRITE_INTERVAL = 1
AIRODUMP_START_DELAY = 0.8


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def list_network_interfaces() -> List[str]:
    return core_list_network_interfaces()


def get_interface_chipset(interface: str) -> str:
    return core_get_interface_chipset(interface)


def select_interface(interfaces: List[str]) -> str:
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)

    logging.info("")
    logging.info(style("Available interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        display_name = f"{name} (AP running)" if name == "wlan0" else name
        label = f"{index}) {display_name} -"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)

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
        logging.warning("Invalid selection. Try again.")


def get_interface_mode(interface: str) -> Optional[str]:
    return core_get_interface_mode(interface, fallback_iwconfig=False)


def is_monitor_mode(interface: str) -> bool:
    return get_interface_mode(interface) == "monitor"


def wait_for_monitor_settle(interface: str) -> None:
    _ = interface
    core_wait_for_monitor_settle(MONITOR_SETTLE_SECONDS)


def set_interface_type(interface: str, mode: str) -> bool:
    ok, error = core_set_interface_type(
        interface,
        mode,
        enable_otherbss=(mode == "monitor"),
        settle_seconds=0.5,
    )
    if ok:
        return True
    logging.error("Failed to set %s mode: %s", mode, error or "unknown error")
    return False


def restore_managed_mode(interface: str) -> None:
    core_restore_managed_mode(interface)


def freq_to_channel(freq: float) -> Optional[int]:
    if 2412 <= freq <= 2472:
        return int((freq - 2407) // 5)
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5825:
        return int((freq - 5000) // 5)
    return None


def channel_to_freq_mhz(channel: Optional[int]) -> Optional[int]:
    if channel is None:
        return None
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if 32 <= channel <= 196:
        return 5000 + channel * 5
    return None


def parse_channel_value(text: str) -> Optional[int]:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def parse_freq_value(text: str) -> Optional[float]:
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    if value > 100000:
        value /= 1000.0
    return value


def is_scan_busy_error(stderr: str) -> bool:
    if not stderr:
        return False
    lower = stderr.lower()
    return "resource busy" in lower or "device or resource busy" in lower or "(-16)" in lower


def normalize_mac_prefix(text: str) -> Optional[str]:
    if not text:
        return None
    cleaned = text.replace(":", "").replace("-", "").strip().upper()
    if len(cleaned) < 6:
        return None
    return cleaned[:6]


def load_vendor_db(path: str) -> Dict[str, str]:
    if not path or not os.path.isfile(path):
        return {}
    vendors: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" in line:
                parts = [part.strip() for part in line.split("|")]
                if len(parts) >= 2:
                    prefix = normalize_mac_prefix(parts[0])
                    vendor = parts[1]
                else:
                    continue
            else:
                tokens = line.split(None, 1)
                prefix = normalize_mac_prefix(tokens[0]) if tokens else None
                vendor = tokens[1].strip() if len(tokens) > 1 else ""
            if prefix:
                vendors[prefix] = vendor
    return vendors


def lookup_vendor(mac_address: Optional[str], vendors: Dict[str, str]) -> Optional[str]:
    if not mac_address or not vendors:
        return None
    prefix = normalize_mac_prefix(mac_address)
    if not prefix:
        return None
    vendor = vendors.get(prefix)
    if vendor:
        return vendor
    return None


def shorten_vendor(vendor: Optional[str], max_len: int = 22) -> Optional[str]:
    if not vendor:
        return None
    cleaned = " ".join(vendor.split())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


def format_ssid(ssid: Optional[str], max_len: int = 24) -> str:
    if not ssid:
        return "<hidden>"
    cleaned = " ".join(ssid.split())
    if not cleaned:
        return "<hidden>"
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


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


def scan_wireless_networks_iw(
    interface: str,
    duration_seconds: int = 15,
    show_progress: bool = False,
) -> List[Dict[str, Optional[str]]]:
    def run_scan(timeout_seconds: float) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

    end_time = time.time() + max(1, duration_seconds)
    networks: Dict[str, Dict[str, Optional[str]]] = {}
    last_remaining = None
    while time.time() < end_time:
        if show_progress and COLOR_ENABLED:
            remaining = max(0, int(end_time - time.time()))
            if remaining != last_remaining:
                last_remaining = remaining
                message = (
                    f"{style('Scanning', STYLE_BOLD)}... "
                    f"{style(str(remaining), COLOR_SUCCESS, STYLE_BOLD)}s remaining"
                )
                sys.stdout.write("\r" + message)
                sys.stdout.flush()
        try:
            remaining_time = end_time - time.time()
            if remaining_time <= 0:
                break
            timeout_seconds = max(1.0, min(SCAN_COMMAND_TIMEOUT, remaining_time))
            result = run_scan(timeout_seconds)
        except FileNotFoundError:
            logging.error("Required tool 'iw' not found!")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []
        except subprocess.TimeoutExpired:
            time.sleep(0.2)
            continue

        if result.returncode != 0 and is_monitor_mode(interface):
            if set_interface_type(interface, "managed"):
                remaining_time = end_time - time.time()
                if remaining_time <= 0:
                    break
                timeout_seconds = max(1.0, min(SCAN_COMMAND_TIMEOUT, remaining_time))
                result = run_scan(timeout_seconds)
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to restore monitor mode after scan.")
                else:
                    time.sleep(0.5)

        if result.returncode != 0:
            err_text = result.stderr.strip()
            if is_scan_busy_error(err_text):
                time.sleep(SCAN_BUSY_RETRY_DELAY)
                continue
            logging.error("Wireless scan failed: %s", err_text or "unknown error")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        current: Dict[str, Optional[str]] = {
            "bssid": None,
            "ssid": None,
            "signal": None,
            "channel": None,
            "encryption": None,
            "wps": None,
        }
        privacy = False
        wpa = False
        wpa2 = False
        wps = False

        def finalize_current() -> None:
            nonlocal current, privacy, wpa, wpa2, wps
            if current.get("bssid"):
                encryption = finalize_encryption(privacy, wpa, wpa2, wps)
                current["encryption"] = encryption
                current["wps"] = "yes" if wps else "no"
                existing = networks.get(current["bssid"])
                if existing is None or (
                    current.get("signal") is not None
                    and (existing.get("signal") is None or current["signal"] > existing["signal"])
                ):
                    networks[current["bssid"]] = current
            current = {
                "bssid": None,
                "ssid": None,
                "signal": None,
                "channel": None,
                "encryption": None,
                "wps": None,
            }
            privacy = False
            wpa = False
            wpa2 = False
            wps = False

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                finalize_current()
                current["bssid"] = line.split()[1].split("(")[0]
                continue
            if line.startswith("freq:"):
                parts = line.split()
                freq_val = parse_freq_value(parts[1]) if len(parts) > 1 else None
                current["channel"] = freq_to_channel(freq_val) if freq_val is not None else None
                continue
            if line.startswith("DS Parameter set:"):
                parts = line.split()
                if len(parts) >= 4 and parts[-2] == "channel":
                    channel_val = parse_channel_value(parts[-1])
                    if channel_val is not None:
                        current["channel"] = channel_val
                continue
            if line.startswith("* primary channel:"):
                parts = line.split(":")
                if len(parts) == 2:
                    channel_val = parse_channel_value(parts[1].strip())
                    if channel_val is not None:
                        current["channel"] = channel_val
                continue
            if line.startswith("signal:"):
                parts = line.split()
                try:
                    current["signal"] = float(parts[1])
                except (IndexError, ValueError):
                    current["signal"] = None
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
                ssid_val = line.split(":", 1)[1].strip()
                current["ssid"] = ssid_val if ssid_val else "<hidden>"
                continue

        finalize_current()

        time.sleep(0.2)

    if show_progress and COLOR_ENABLED:
        sys.stdout.write("\n")

    sorted_networks = sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )
    return sorted_networks


def display_iw_results(networks: List[Dict[str, Optional[str]]], vendors: Dict[str, str]) -> None:
    if not networks:
        logging.warning("No networks found.")
        return

    logging.info("")
    logging.info(style("Available networks:", STYLE_BOLD))
    for index, net in enumerate(networks, start=1):
        signal = f"{net['signal']:.1f} dBm" if net["signal"] is not None else "signal ?"
        channel = f"ch {net['channel']}" if net["channel"] else "ch ?"
        encryption = net.get("encryption") or "UNKNOWN"
        bssid = net.get("bssid") or "??"
        ssid = format_ssid(net.get("ssid"))
        vendor = lookup_vendor(bssid, vendors)
        vendor_label = f" | {vendor}" if vendor else ""
        label = f"{index}) {ssid} ({bssid}) -"
        logging.info(
            "  %s %s | %s | %s%s",
            color_text(label, COLOR_HIGHLIGHT),
            channel,
            encryption,
            signal,
            vendor_label,
        )


def parse_channels(text: str) -> List[int]:
    if not text:
        return []
    text = text.strip()
    channels: List[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                continue
            for ch in range(min(start, end), max(start, end) + 1):
                channels.append(ch)
        else:
            try:
                channels.append(int(part))
            except ValueError:
                continue
    return sorted(set(channels))


def rssi_to_quality(rssi: Optional[int]) -> Optional[int]:
    if rssi is None:
        return None
    if rssi >= -50:
        return 100
    value = 2 * (rssi + 100)
    if value < 0:
        return 0
    if value > 100:
        return 100
    return value


def normalize_mac(mac_address: Optional[str]) -> Optional[str]:
    if not mac_address:
        return None
    return mac_address.strip().lower()


def is_unicast(mac_address: Optional[str]) -> bool:
    if not is_valid_mac(mac_address):
        return False
    try:
        first_octet = int(mac_address.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first_octet & 1) == 0


def is_valid_mac(mac_address: Optional[str]) -> bool:
    lower = normalize_mac(mac_address)
    if not lower:
        return False
    if lower in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    if lower.startswith(("01:00:5e", "01:80:c2", "33:33")):
        return False
    if len(lower.split(":")) != 6:
        return False
    return True


def parse_int_value(text: str) -> Optional[int]:
    try:
        return int(text.strip())
    except (AttributeError, ValueError):
        return None


def parse_airodump_encryption(privacy: str, cipher: str, auth: str) -> str:
    combined = " ".join([privacy or "", cipher or "", auth or ""]).upper()
    if "WPA3" in combined:
        encryption = "WPA3"
    elif "WPA2" in combined:
        encryption = "WPA2"
    elif "WPA" in combined:
        encryption = "WPA"
    elif "WEP" in combined:
        encryption = "WEP"
    elif "OPN" in combined or "OPEN" in combined:
        encryption = "OPEN"
    else:
        encryption = "UNKNOWN"
    if encryption not in ("WEP", "UNKNOWN") and "WPS" in combined:
        encryption = f"{encryption}/WPS"
    return encryption


def parse_probed_essids(text: str) -> Set[str]:
    if not text:
        return set()
    parsed: Set[str] = set()
    for raw_item in text.split(","):
        item = raw_item.strip()
        if not item:
            continue
        if item in ("<hidden>", "<non-printable>"):
            continue
        parsed.add(item)
    return parsed


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: Optional[int]
    frequency: Optional[int]
    encryption: str
    rssi: Optional[int]
    signal: Optional[int]
    clients: Set[str] = field(default_factory=set)

    def update_signal(self, new_rssi: Optional[int]) -> None:
        new_signal = rssi_to_quality(new_rssi)
        if new_signal is None:
            return
        if self.signal is None or new_signal > self.signal + 5:
            self.signal = new_signal
            self.rssi = new_rssi


@dataclass
class SnifferState:
    aps: Dict[str, "AccessPoint"] = field(default_factory=dict)
    probe_counts: Dict[str, int] = field(default_factory=dict)
    packet_count: int = 0
    probe_total: int = 0
    probe_pair_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)
    probe_pair_last_seen: Dict[Tuple[str, str], float] = field(default_factory=dict)


@dataclass
class AirodumpSnapshot:
    aps: Dict[str, AccessPoint] = field(default_factory=dict)
    probes_by_station: Dict[str, Set[str]] = field(default_factory=dict)
    packet_count: int = 0


def clone_access_point(ap: AccessPoint) -> AccessPoint:
    return AccessPoint(
        ssid=ap.ssid,
        bssid=ap.bssid,
        channel=ap.channel,
        frequency=ap.frequency,
        encryption=ap.encryption,
        rssi=ap.rssi,
        signal=ap.signal,
        clients=set(ap.clients),
    )


def clone_access_points(aps: Dict[str, AccessPoint]) -> Dict[str, AccessPoint]:
    return {bssid: clone_access_point(ap) for bssid, ap in aps.items()}


def merge_access_point(existing: AccessPoint, incoming: AccessPoint) -> None:
    if existing.ssid == "<hidden>" and incoming.ssid != "<hidden>":
        existing.ssid = incoming.ssid
    if incoming.channel and not existing.channel:
        existing.channel = incoming.channel
    if incoming.frequency and not existing.frequency:
        existing.frequency = incoming.frequency
    if incoming.encryption and incoming.encryption != "UNKNOWN":
        if existing.encryption == "UNKNOWN" or existing.encryption != incoming.encryption:
            existing.encryption = incoming.encryption
    existing.update_signal(incoming.rssi)
    existing.clients.update(incoming.clients)


def cleanup_capture_dir(capture_dir: str) -> None:
    if not os.path.isdir(capture_dir):
        return
    for filename in os.listdir(capture_dir):
        path = os.path.join(capture_dir, filename)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass
    try:
        os.rmdir(capture_dir)
    except OSError:
        pass


def stop_airodump_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception:
        process.terminate()
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except Exception:
            process.kill()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass


def start_airodump_capture(interface: str, output_prefix: str, channels: List[int]) -> subprocess.Popen:
    command = [
        "airodump-ng",
        "--write-interval",
        str(AIRODUMP_WRITE_INTERVAL),
        "--output-format",
        "csv",
        "-w",
        output_prefix,
    ]
    if channels:
        command.extend(["--channel", ",".join(str(ch) for ch in channels)])
    command.append(interface)
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,
    )
    time.sleep(AIRODUMP_START_DELAY)
    if process.poll() is not None:
        error = (process.stderr.read() if process.stderr else "").strip()
        raise RuntimeError(error or "airodump-ng exited immediately.")
    return process


def parse_airodump_csv(csv_path: str) -> AirodumpSnapshot:
    snapshot = AirodumpSnapshot()
    if not os.path.isfile(csv_path):
        return snapshot

    section = ""
    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                if not row or not any(cell.strip() for cell in row):
                    continue

                first = row[0].strip()
                if first == "BSSID":
                    section = "aps"
                    continue
                if first == "Station MAC":
                    section = "stations"
                    continue

                if section == "aps":
                    bssid = normalize_mac(row[0] if len(row) > 0 else None)
                    if not is_valid_mac(bssid):
                        continue

                    channel = parse_channel_value(row[3].strip()) if len(row) > 3 else None
                    privacy = row[5].strip() if len(row) > 5 else ""
                    cipher = row[6].strip() if len(row) > 6 else ""
                    auth = row[7].strip() if len(row) > 7 else ""
                    encryption = parse_airodump_encryption(privacy, cipher, auth)

                    rssi = parse_int_value(row[8]) if len(row) > 8 else None
                    if rssi is not None:
                        if rssi >= 0:
                            rssi = -abs(rssi)
                        if rssi == -1:
                            rssi = None

                    ssid = row[13].strip() if len(row) > 13 else ""
                    if not ssid:
                        ssid = "<hidden>"

                    ap = AccessPoint(
                        ssid=ssid,
                        bssid=bssid or "",
                        channel=channel,
                        frequency=channel_to_freq_mhz(channel),
                        encryption=encryption,
                        rssi=rssi,
                        signal=rssi_to_quality(rssi),
                    )
                    existing = snapshot.aps.get(ap.bssid)
                    if existing is None:
                        snapshot.aps[ap.bssid] = ap
                    else:
                        merge_access_point(existing, ap)

                    beacons = parse_int_value(row[9]) if len(row) > 9 else 0
                    data_packets = parse_int_value(row[10]) if len(row) > 10 else 0
                    snapshot.packet_count += max(0, beacons or 0) + max(0, data_packets or 0)
                    continue

                if section != "stations":
                    continue

                station_mac = normalize_mac(row[0] if len(row) > 0 else None)
                if not is_valid_mac(station_mac):
                    continue

                packets = parse_int_value(row[4]) if len(row) > 4 else 0
                snapshot.packet_count += max(0, packets or 0)

                bssid = normalize_mac(row[5] if len(row) > 5 else None)
                if is_valid_mac(bssid):
                    if bssid not in snapshot.aps:
                        snapshot.aps[bssid] = AccessPoint(
                            ssid="<hidden>",
                            bssid=bssid,
                            channel=None,
                            frequency=None,
                            encryption="UNKNOWN",
                            rssi=None,
                            signal=None,
                        )
                    if station_mac != bssid and is_unicast(station_mac):
                        snapshot.aps[bssid].clients.add(station_mac)

                probe_field = ",".join(part.strip() for part in row[6:]) if len(row) > 6 else ""
                probes = parse_probed_essids(probe_field)
                if probes and station_mac:
                    snapshot.probes_by_station[station_mac] = probes
    except OSError:
        return AirodumpSnapshot()

    return snapshot


def scan_wireless_networks_aircrack(
    interface: str,
    duration_seconds: int,
    channels: List[int],
    hop_interval: float,
    update_interval: float = DEFAULT_LIVE_UPDATE_INTERVAL,
    on_update: Optional[Callable[[Dict[str, "AccessPoint"], int], None]] = None,
) -> Dict[str, AccessPoint]:
    _ = hop_interval
    capture_dir = tempfile.mkdtemp(prefix="swissknife_recon_scan_")
    output_prefix = os.path.join(capture_dir, "capture")
    csv_path = f"{output_prefix}-01.csv"
    process: Optional[subprocess.Popen] = None
    latest_snapshot = AirodumpSnapshot()

    try:
        process = start_airodump_capture(interface, output_prefix, channels)
        end_time = time.time() + max(1, duration_seconds)
        while time.time() < end_time:
            if process.poll() is not None:
                error = (process.stderr.read() if process.stderr else "").strip()
                if error:
                    logging.error("Scanner stopped: %s", error)
                break
            latest_snapshot = parse_airodump_csv(csv_path)
            if on_update:
                remaining = max(0, int(end_time - time.time()))
                on_update(clone_access_points(latest_snapshot.aps), remaining)
            time.sleep(max(0.2, update_interval))

        final_snapshot = parse_airodump_csv(csv_path)
        if final_snapshot.aps:
            latest_snapshot = final_snapshot
        return latest_snapshot.aps
    except FileNotFoundError:
        logging.error("Required tool 'airodump-ng' not found!")
        return {}
    except RuntimeError as exc:
        logging.error("Airodump scan failed: %s", exc)
        return {}
    finally:
        if process is not None:
            stop_airodump_process(process)
        cleanup_capture_dir(capture_dir)


def format_scan_results_lines(aps: Dict[str, AccessPoint], vendors: Dict[str, str]) -> List[str]:
    if not aps:
        return [color_text("No access points found.", COLOR_WARNING)]

    sorted_aps = sorted(
        aps.values(),
        key=lambda ap: ap.signal if ap.signal is not None else -1,
        reverse=True,
    )

    lines: List[str] = [style("Observed access points:", STYLE_BOLD)]
    for index, ap in enumerate(sorted_aps, start=1):
        channel = f"ch {ap.channel}" if ap.channel else "ch ?"
        rssi = f"{ap.rssi} dBm" if ap.rssi is not None else "rssi ?"
        clients = f"clients {len(ap.clients)}"
        vendor = shorten_vendor(lookup_vendor(ap.bssid, vendors))
        label = f"{index}) {format_ssid(ap.ssid)} ({ap.bssid}) -"
        details = f"{channel} | {ap.encryption} | {rssi} | {clients}"
        if vendor:
            details += f" | {vendor}"
        lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {details}")

    return lines


def display_scan_results(aps: Dict[str, AccessPoint], vendors: Dict[str, str]) -> None:
    lines = format_scan_results_lines(aps, vendors)
    logging.info("")
    for line in lines:
        logging.info("%s", line)


def display_scan_live_update(
    aps: Dict[str, AccessPoint],
    vendors: Dict[str, str],
    remaining: int,
    interface: str,
) -> None:
    header = style(f"Scaner on {interface}", STYLE_BOLD)
    progress = (
        f"{style('Scanning', STYLE_BOLD)}... "
        f"{style(str(remaining), COLOR_SUCCESS, STYLE_BOLD)}s remaining"
    )
    lines = [header, progress, ""]
    lines.extend(format_scan_results_lines(aps, vendors))
    output = "\n".join(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


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


def format_client_list(clients: Set[str], max_items: int = 3) -> str:
    if not clients:
        return ""
    sorted_clients = sorted(clients)
    if len(sorted_clients) <= max_items:
        return ", ".join(sorted_clients)
    remaining = len(sorted_clients) - max_items
    shown = ", ".join(sorted_clients[:max_items])
    return f"{shown} +{remaining}"


def build_box(lines: List[str]) -> str:
    width = max(len(line) for line in lines)
    border = "+" + "-" * (width + 2) + "+"
    body = [f"| {line.ljust(width)} |" for line in lines]
    return "\n".join([border, *body, border])


def display_sniffer_live(
    packet_count: int,
    probe_total: int,
    probe_unique: int,
    interface: str,
    status: str,
    control_hint: Optional[str] = None,
) -> None:
    if control_hint is None:
        control_hint = style("Press Enter to stop.", COLOR_SUCCESS, STYLE_BOLD)
    lines = [
        f"Sniffer on {interface}",
        f"Packets: {packet_count}",
        f"Probes:  {probe_total} (SSID: {probe_unique})",
        f"Status:  {status.upper()}",
        control_hint,
    ]
    output = build_box(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


def format_sniffer_networks_lines(aps: Dict[str, AccessPoint], vendors: Dict[str, str]) -> List[str]:
    if not aps:
        return [color_text("No networks found.", COLOR_WARNING)]

    sorted_aps = sorted(
        aps.values(),
        key=lambda ap: (len(ap.clients), ap.signal if ap.signal is not None else -1),
        reverse=True,
    )

    lines: List[str] = [style("Observed networks:", STYLE_BOLD)]
    for index, ap in enumerate(sorted_aps, start=1):
        channel = f"ch {ap.channel}" if ap.channel else "ch ?"
        rssi = f"{ap.rssi} dBm" if ap.rssi is not None else "rssi ?"
        client_count = len(ap.clients)
        client_list = format_client_list(ap.clients)
        client_label = f"clients {client_count}"
        if client_list:
            client_label += f" ({client_list})"
        vendor = shorten_vendor(lookup_vendor(ap.bssid, vendors))
        label = f"{index}) {format_ssid(ap.ssid)} ({ap.bssid}) -"
        details = f"{channel} | {ap.encryption} | {rssi} | {client_label}"
        if vendor:
            details += f" | {vendor}"
        lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {details}")
    return lines


def format_probe_lines(probe_counts: Dict[str, int], probe_total: int) -> List[str]:
    if not probe_counts:
        return [color_text("No probe requests observed.", COLOR_WARNING)]

    lines: List[str] = [
        style("Observed probes:", STYLE_BOLD),
        style(f"Total probes: {probe_total} | Unique SSIDs: {len(probe_counts)}", STYLE_BOLD),
    ]
    for ssid, count in sorted(probe_counts.items(), key=lambda item: item[1], reverse=True):
        lines.append(f"  {color_text(ssid, COLOR_HIGHLIGHT)} - {count}")
    return lines


def merge_snapshot_into_state(
    state: SnifferState,
    snapshot: AirodumpSnapshot,
    packet_offset: int,
    now_ts: Optional[float] = None,
) -> None:
    now_value = now_ts or time.time()
    for bssid, ap in snapshot.aps.items():
        existing = state.aps.get(bssid)
        if existing is None:
            state.aps[bssid] = clone_access_point(ap)
            continue
        merge_access_point(existing, ap)

    state.packet_count = max(state.packet_count, packet_offset + snapshot.packet_count)

    for station, probes in snapshot.probes_by_station.items():
        for ssid in probes:
            key = (station, ssid)
            last_seen = state.probe_pair_last_seen.get(key, 0.0)
            state.probe_pair_last_seen[key] = now_value
            if now_value - last_seen < 1.2:
                continue
            state.probe_pair_counts[key] = state.probe_pair_counts.get(key, 0) + 1
            state.probe_counts[ssid] = state.probe_counts.get(ssid, 0) + 1
            state.probe_total += 1


def run_sniffer(
    interface: str,
    stop_event: threading.Event,
    state: SnifferState,
    channels: Optional[List[int]] = None,
    hop_interval: float = DEFAULT_HOP_INTERVAL,
    update_interval: float = 1.0,
    display_live: bool = True,
    control_hint: Optional[str] = None,
    on_update: Optional[Callable[[SnifferState, str], None]] = None,
) -> None:
    if control_hint is None:
        control_hint = style("Press Enter to stop.", COLOR_SUCCESS, STYLE_BOLD)
    _ = hop_interval
    capture_dir = tempfile.mkdtemp(prefix="swissknife_recon_sniffer_")
    output_prefix = os.path.join(capture_dir, "capture")
    csv_path = f"{output_prefix}-01.csv"
    process: Optional[subprocess.Popen] = None
    status = "starting"
    packet_offset = state.packet_count

    try:
        process = start_airodump_capture(interface, output_prefix, channels or [])
        status = "running"

        while not stop_event.is_set():
            if process.poll() is not None:
                status = "error"
                error = (process.stderr.read() if process.stderr else "").strip()
                if error:
                    logging.error("Sniffer stopped: %s", error)
                break

            snapshot = parse_airodump_csv(csv_path)
            merge_snapshot_into_state(state, snapshot, packet_offset, now_ts=time.time())
            if display_live:
                display_sniffer_live(
                    state.packet_count,
                    state.probe_total,
                    len(state.probe_counts),
                    interface,
                    status,
                    control_hint=control_hint,
                )
            if on_update:
                on_update(state, status)
            time.sleep(max(0.2, update_interval))

    except FileNotFoundError:
        status = "error"
        logging.error("Required tool 'airodump-ng' not found!")
    except RuntimeError as exc:
        status = "error"
        logging.error("Failed to start sniffer: %s", exc)
    finally:
        if process is not None:
            stop_airodump_process(process)
        final_snapshot = parse_airodump_csv(csv_path)
        merge_snapshot_into_state(state, final_snapshot, packet_offset, now_ts=time.time())
        if on_update:
            on_update(state, status)
        cleanup_capture_dir(capture_dir)
    stop_event.set()


def recon_menu(vendors: Dict[str, str]) -> None:
    while True:
        logging.info("")
        logging.info(style("Recon menu:", STYLE_BOLD))
        logging.info("  %s", color_text("[1] Scaner (aircrack-ng)", COLOR_HIGHLIGHT))
        logging.info("  %s", color_text("[2] Sniffer (aircrack-ng)", COLOR_HIGHLIGHT))
        logging.info("  %s", color_text("[0] Back", COLOR_HIGHLIGHT))

        choice = input(style("Your choice (0-2): ", STYLE_BOLD)).strip()
        if choice == "0":
            return

        if choice == "1":
            interfaces = list_network_interfaces()
            interface = select_interface(interfaces)

            original_mode = get_interface_mode(interface)
            if original_mode != "monitor":
                logging.info("")
                input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to switch {interface} to monitor mode...")
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to enable monitor mode on %s.", interface)
                    continue
                wait_for_monitor_settle(interface)

            logging.info("")
            duration = prompt_int(
                f"{style('Scan duration', STYLE_BOLD)} in seconds "
                f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} for {style('12', COLOR_SUCCESS, STYLE_BOLD)}): ",
                default=12,
            )

            logging.info("")
            input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start scaner on {interface}...")
            live_update = lambda snapshot, remaining: display_scan_live_update(
                snapshot, vendors, remaining, interface
            )
            aps = scan_wireless_networks_aircrack(
                interface,
                duration,
                DEFAULT_MONITOR_CHANNELS,
                DEFAULT_HOP_INTERVAL,
                update_interval=DEFAULT_LIVE_UPDATE_INTERVAL,
                on_update=live_update,
            )
            display_scan_results(aps, vendors)

            if original_mode and original_mode != "monitor":
                restore_managed_mode(interface)
            input(style("Press Enter to return.", COLOR_SUCCESS, STYLE_BOLD))
            continue

        if choice == "2":
            interfaces = list_network_interfaces()
            interface = select_interface(interfaces)

            original_mode = get_interface_mode(interface)
            if original_mode != "monitor":
                logging.info("")
                input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to switch {interface} to monitor mode...")
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to enable monitor mode on %s.", interface)
                    continue
                wait_for_monitor_settle(interface)

            state = SnifferState()
            first_run = True
            while True:
                logging.info("")
                if first_run:
                    input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start sniffer on {interface}...")
                    first_run = False
                stop_event = threading.Event()

                def wait_for_stop() -> None:
                    try:
                        input()
                    except EOFError:
                        pass
                    stop_event.set()

                stopper = threading.Thread(target=wait_for_stop, daemon=True)
                stopper.start()

                run_sniffer(
                    interface,
                    stop_event,
                    state,
                    channels=DEFAULT_MONITOR_CHANNELS,
                    hop_interval=DEFAULT_HOP_INTERVAL,
                )
                stopper.join(timeout=1)

                logging.info("")
                logging.info(style(f"Total packets captured: {state.packet_count}", STYLE_BOLD))
                for line in format_sniffer_networks_lines(state.aps, vendors):
                    logging.info("%s", line)
                logging.info("")
                for line in format_probe_lines(state.probe_counts, state.probe_total):
                    logging.info("%s", line)

                logging.info("")
                logging.info(style("Options:", STYLE_BOLD))
                logging.info("  %s", color_text("[0] Back to main menu", COLOR_HIGHLIGHT))
                logging.info("  %s", color_text("[2] Resume sniffer", COLOR_HIGHLIGHT))
                while True:
                    selection = input(style("Your choice (0/2): ", STYLE_BOLD)).strip()
                    if selection in ("0", "2"):
                        break
                    logging.warning("Invalid choice.")
                if selection == "2":
                    continue
                if original_mode and original_mode != "monitor":
                    restore_managed_mode(interface)
                return

        logging.warning("Invalid choice.")


def main() -> None:
    logging.info(color_text("Recon Toolkit", COLOR_HEADER))
    logging.info("Passive wireless discovery and inventory")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool", "airodump-ng"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    vendors = load_vendor_db(DEFAULT_VENDOR_DB)
    if not vendors:
        logging.info(
            "Vendor lookup: disabled (set SWISSKNIFE_VENDOR_DB or add data/oui.txt)."
        )
    else:
        logging.info("Vendor lookup: enabled (%d entries).", len(vendors))

    recon_menu(vendors)


if __name__ == "__main__":
    main()
