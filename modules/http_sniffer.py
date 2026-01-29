#!/usr/bin/env python3

import os
import sys
import time
import logging
import subprocess
from datetime import datetime
from typing import List, Optional, TextIO, Tuple

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

try:
    from scapy.all import sniff, Raw, IP, conf  # type: ignore
    from scapy.layers.http import HTTPRequest  # type: ignore
    SCAPY_AVAILABLE = True
    conf.verb = 0
except Exception:
    SCAPY_AVAILABLE = False
    HTTPRequest = None  # type: ignore
    Raw = None  # type: ignore
    IP = None  # type: ignore


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def list_network_interfaces() -> List[str]:
    interfaces: List[str] = []
    ip_link = subprocess.run(["ip", "-o", "link", "show"], stdout=subprocess.PIPE, text=True, check=False)
    for line in ip_link.stdout.splitlines():
        if ": " in line:
            name = line.split(": ", 1)[1].split(":", 1)[0]
            if name and name != "lo":
                interfaces.append(name)
    return interfaces


def get_interface_chipset(interface: str) -> str:
    try:
        result = subprocess.run(
            ["ethtool", "-i", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return "unknown"

    if result.returncode != 0:
        return "unknown"

    driver = None
    bus_info = None
    for line in result.stdout.splitlines():
        if line.startswith("driver:"):
            driver = line.split(":", 1)[1].strip()
        if line.startswith("bus-info:"):
            bus_info = line.split(":", 1)[1].strip()

    if driver and bus_info and bus_info != "":
        return f"{driver} ({bus_info})"
    if driver:
        return driver
    return "unknown"


def get_default_interface() -> Optional[str]:
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None


def select_interface(interfaces: List[str], default_iface: Optional[str]) -> str:
    if interfaces:
        logging.info("")
        logging.info(style("Available interfaces:", STYLE_BOLD))
        for index, name in enumerate(interfaces, start=1):
            chipset = get_interface_chipset(name)
            label = f"{index}) {name} -"
            logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)
    else:
        logging.warning("No network interfaces detected.")

    while True:
        default_hint = f" (Enter for {default_iface})" if default_iface else ""
        choice = input(f"{style('Select interface', STYLE_BOLD)}{default_hint}: ").strip()
        if not choice:
            if default_iface:
                return default_iface
            if not interfaces:
                logging.warning("Please enter an interface name.")
                continue
        if choice.isdigit() and interfaces:
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
        if choice in interfaces or (choice and not interfaces):
            return choice
        logging.warning("Invalid selection. Try again.")


def prompt_duration() -> Optional[int]:
    raw = input(
        f"{style('Capture duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for unlimited): "
    ).strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        logging.warning("Invalid duration. Using unlimited.")
        return None
    if value <= 0:
        logging.warning("Duration must be greater than zero. Using unlimited.")
        return None
    return value


def safe_decode(value: Optional[bytes]) -> str:
    if not value:
        return ""
    try:
        return value.decode("utf-8", errors="ignore")
    except Exception:
        return str(value)


def create_log_file(prefix: str) -> Tuple[TextIO, str]:
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.txt"
    path = os.path.join(LOG_DIR, filename)
    handle = open(path, "w", encoding="utf-8")
    return handle, path


def log_event(handle: TextIO, message: str, color: Optional[str] = None) -> None:
    if color:
        logging.info(color_text(message, color))
    else:
        logging.info(message)
    handle.write(message + "\n")
    handle.flush()


class SnifferState:
    def __init__(self, log_handle: TextIO) -> None:
        self.log_handle = log_handle
        self.count = 0


def packet_handler(packet, state: SnifferState) -> None:
    if not HTTPRequest or not packet.haslayer(HTTPRequest):
        return
    req = packet[HTTPRequest]
    method = safe_decode(getattr(req, "Method", b""))
    host = safe_decode(getattr(req, "Host", b""))
    path = safe_decode(getattr(req, "Path", b""))
    url = f"{host}{path}" if host or path else "<unknown>"
    src_ip = packet[IP].src if IP and packet.haslayer(IP) else "unknown"
    dst_ip = packet[IP].dst if IP and packet.haslayer(IP) else "unknown"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"{timestamp} {src_ip} -> {dst_ip} {method} {url}"
    state.count += 1
    log_event(state.log_handle, line, COLOR_HIGHLIGHT)

    if Raw and packet.haslayer(Raw) and method.upper() == "POST":
        raw_data = bytes(packet[Raw].load)
        preview = safe_decode(raw_data[:200])
        if preview:
            log_event(state.log_handle, f"{timestamp} POST data: {preview}")


def main() -> None:
    logging.info(color_text("HTTP Sniffer", COLOR_HEADER))
    logging.info("Capture HTTP requests (port 80)")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not SCAPY_AVAILABLE:
        logging.error("Scapy is not installed. Install with: pip3 install scapy")
        sys.exit(1)

    required_tools = ["ip", "ethtool"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    logging.info(style("IMPORTANT:", COLOR_WARNING, STYLE_BOLD))
    logging.info("Use only on networks you own or have explicit permission to test.")

    interfaces = list_network_interfaces()
    default_iface = get_default_interface()
    interface = select_interface(interfaces, default_iface)
    duration = prompt_duration()

    logging.info("")
    log_handle, log_path = create_log_file("http_sniffer")
    log_event(log_handle, f"Log file: {log_path}", COLOR_SUCCESS)
    log_event(log_handle, f"Interface: {interface}")
    log_event(log_handle, "Filter: tcp port 80")

    logging.info("")
    logging.info(style("Sniffing started. Press Ctrl+C to stop.", STYLE_BOLD))

    state = SnifferState(log_handle)
    try:
        sniff(
            filter="tcp port 80",
            iface=interface,
            prn=lambda pkt: packet_handler(pkt, state),
            store=False,
            timeout=duration,
        )
    except KeyboardInterrupt:
        logging.info("")
        logging.info(color_text("Stopping sniffer...", COLOR_WARNING))
    finally:
        log_handle.close()

    logging.info("")
    logging.info(style(f"Captured {state.count} HTTP request(s).", STYLE_BOLD))
    logging.info(f"Log saved to: {log_path}")
    input(style("Press Enter to return.", STYLE_BOLD))


if __name__ == "__main__":
    main()
