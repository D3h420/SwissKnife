#!/usr/bin/env python3

"""
Simple launcher that combines the existing attacks into one menu (Airgeddon style).
Each choice runs a separate script and returns to the menu when it exits.
"""

import os
import subprocess
import sys
import shutil
import platform
import importlib.util
from typing import Dict, List, Optional, Tuple

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


ASCII_HEADER = r"""
██╗      █████╗ ██████╗ ███████╗
██║     ██╔══██╗██╔══██╗██╔════╝
██║     ███████║██████╔╝███████╗
██║     ██╔══██║██╔══██╗╚════██║
███████╗██║  ██║██████╔╝███████║
╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝

wireless swiss knife
"""

MAIN_MENU: Dict[str, Dict[str, str]] = {
    "1": {"name": "Recon", "action": "recon"},
    "2": {"name": "Attacks", "action": "attacks"},
    "3": {"name": "Bluetooth", "action": "bluetooth"},
    "0": {"name": "Exit", "action": "exit"},
}

ATTACKS_MENU: Dict[str, Dict[str, str]] = {
    "basic": {"name": "-BASIC-", "separator": True},
    "1": {"name": "Deauth", "file": os.path.join("modules", "deauth.py")},
    "2": {"name": "Portal", "file": os.path.join("modules", "portal.py")},
    "3": {"name": "Evil Twin", "file": os.path.join("modules", "twins.py")},
    "4": {"name": "Handshaker", "file": os.path.join("modules", "handshaker.py")},
    "5": {"name": "WiFi Poet", "file": os.path.join("modules", "wifi_poet.py")},
    "6": {"name": "Dragon Drain", "file": os.path.join("modules", "dragon_drain.py")},
    "7": {"name": "Karma (MVP)", "file": os.path.join("modules", "karma.py")},
    "spacer_after_basic": {"name": "", "separator": True},
    "inside": {"name": "-INSIDE-", "separator": True},
    "8": {"name": "ARP scan", "file": os.path.join("modules", "arp_scanner.py")},
    "9": {"name": "IP.CAM finder", "file": os.path.join("modules", "ipcam_finder.py")},
    "spacer": {"name": "", "separator": True},
    "0": {"name": "Back", "file": ""},
}

RECON_SCRIPT = os.path.join("modules", "recon.py")
BLUETOOTH_SCRIPT = os.path.join("modules", "bluetooth.py")
RUNTIME_REQUIREMENTS = "requirements.txt"
RUNTIME_REQUIRED_PY_MODULES: List[str] = [
    "scapy",
]

REQUIRED_TOOLS: List[str] = [
    "iw",
    "ip",
    "ethtool",
    "nmcli",
    "ping",
    "arp-scan",
    "aireplay-ng",
    "airodump-ng",
    "mdk4",
    "bluetoothctl",
    "btmgmt",
    "hostapd",
    "dnsmasq",
    "iptables",
]

RECOMMENDED_TOOLS: List[str] = [
    "airmon-ng",
    "bully",
    "hcitool",
    "git",
    "autoreconf",
    "automake",
    "libtool",
    "make",
    "gcc",
    "pkg-config",
]

PACKAGE_MAPS = {
    "apt": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
        "nmcli": "network-manager",
        "ping": "iputils-ping",
        "hcitool": "bluez",
        "autoreconf": "autoconf",
    },
    "apt-get": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
        "nmcli": "network-manager",
        "ping": "iputils-ping",
        "hcitool": "bluez",
        "autoreconf": "autoconf",
    },
    "dnf": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute",
        "nmcli": "NetworkManager",
        "ping": "iputils",
        "hcitool": "bluez",
        "autoreconf": "autoconf",
        "pkg-config": "pkgconf-pkg-config",
    },
    "yum": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute",
        "nmcli": "NetworkManager",
        "ping": "iputils",
        "hcitool": "bluez",
        "autoreconf": "autoconf",
        "pkg-config": "pkgconf-pkg-config",
    },
    "pacman": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
        "nmcli": "networkmanager",
        "ping": "iputils",
        "hcitool": "bluez-utils",
        "pkg-config": "pkgconf",
    },
    "zypper": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
        "nmcli": "NetworkManager",
        "ping": "iputils",
        "hcitool": "bluez",
        "autoreconf": "autoconf",
    },
    "apk": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "ip": "iproute2",
        "ping": "iputils",
        "nmcli": "networkmanager",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "pkg-config": "pkgconf",
    },
}


def base_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def print_banner() -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    print()


def extended_path_env() -> str:
    extra_paths = ["/sbin", "/usr/sbin", "/usr/local/sbin"]
    env_path = os.environ.get("PATH", "")
    return os.pathsep.join([env_path, *extra_paths])


def tool_exists(tool: str) -> bool:
    return shutil.which(tool, path=extended_path_env()) is not None


def detect_package_manager() -> str:
    if platform.system() == "Darwin":
        return "brew" if shutil.which("brew") else ""

    for candidate in ["apt-get", "apt", "dnf", "yum", "pacman", "zypper", "apk"]:
        if shutil.which(candidate):
            return candidate
    return ""


def package_names(package_manager: str, tools: List[str]) -> List[str]:
    mapping = PACKAGE_MAPS.get(package_manager, {})
    resolved = []
    for tool in tools:
        package = mapping.get(tool, tool)
        if package not in resolved:
            resolved.append(package)
    return resolved


def install_missing_tools(missing: List[str]) -> bool:
    if platform.system() == "Darwin":
        print(color_text("Automatic installation is not supported on macOS. Please install the missing tools manually (e.g., via Homebrew).\n", COLOR_HIGHLIGHT))
        return False

    package_manager = detect_package_manager()
    if not package_manager:
        print(color_text("No supported package manager found; please install tools manually.\n", COLOR_HIGHLIGHT))
        return False

    packages = package_names(package_manager, missing)

    if package_manager in ("apt", "apt-get"):
        cmd = [package_manager, "install", "-y", *packages]
    elif package_manager in ("dnf", "yum"):
        cmd = [package_manager, "install", "-y", *packages]
    elif package_manager == "pacman":
        cmd = ["pacman", "-S", "--noconfirm", "--needed", *packages]
    elif package_manager == "zypper":
        cmd = ["zypper", "--non-interactive", "install", *packages]
    elif package_manager == "apk":
        cmd = ["apk", "add", *packages]
    else:
        print(color_text(f"Unsupported package manager '{package_manager}'. Please install tools manually.\n", COLOR_HIGHLIGHT))
        return False

    print(style(f"Installing missing tools via {package_manager}...", STYLE_BOLD))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(color_text("Automatic installation failed. Please install the remaining tools manually.\n", COLOR_HIGHLIGHT))
        return False

    return True


def prompt_yes_no(message: str, default_yes: bool = True) -> bool:
    try:
        response = input(style(message, STYLE_BOLD)).strip().lower()
    except EOFError:
        return default_yes

    if not response:
        return default_yes
    return response in ("y", "yes")


def missing_python_modules(modules: List[str]) -> List[str]:
    missing: List[str] = []
    for module_name in modules:
        if importlib.util.find_spec(module_name) is None:
            missing.append(module_name)
    return missing


def pip_available() -> bool:
    result = subprocess.run(
        [sys.executable or "python3", "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def install_python_dependencies(requirements_path: str) -> bool:
    base = [sys.executable or "python3", "-m", "pip", "install"]
    attempts = [
        [*base, "-r", requirements_path],
        [*base, "--break-system-packages", "-r", requirements_path],
    ]

    for index, command in enumerate(attempts):
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return True

        output = result.stdout or ""
        lower_output = output.lower()
        if index == 0 and "externally-managed-environment" in lower_output:
            print(color_text("Detected externally managed Python environment; retrying with --break-system-packages.", COLOR_HIGHLIGHT))
            continue

        if output.strip():
            tail = "\n".join(output.strip().splitlines()[-10:])
            print(color_text("pip output (last lines):", COLOR_HIGHLIGHT))
            print(tail)
        break
    return False


def ensure_runtime_python_dependencies() -> bool:
    missing = missing_python_modules(RUNTIME_REQUIRED_PY_MODULES)
    if not missing:
        return True

    print(color_text(f"Missing Python modules for runtime modules: {', '.join(missing)}", COLOR_HIGHLIGHT))
    requirements_path = script_path(RUNTIME_REQUIREMENTS)
    if not os.path.isfile(requirements_path):
        print(color_text(f"Requirements file not found: {requirements_path}", COLOR_HIGHLIGHT))
        print(style(f"Install manually: {sys.executable or 'python3'} -m pip install scapy", STYLE_BOLD))
        return False

    if not pip_available():
        print(color_text("pip is not available for this Python interpreter.", COLOR_HIGHLIGHT))
        print(style(f"Install manually: {sys.executable or 'python3'} -m ensurepip --upgrade", STYLE_BOLD))
        return False

    if not prompt_yes_no("Install runtime Python dependencies now? [Y/n]: "):
        print(style(f"Install manually: {sys.executable or 'python3'} -m pip install -r {requirements_path}", STYLE_BOLD))
        print(style(f"If needed on Debian/Ubuntu: {sys.executable or 'python3'} -m pip install --break-system-packages -r {requirements_path}", STYLE_BOLD))
        return False

    if not install_python_dependencies(requirements_path):
        print(color_text("Automatic Python dependency installation failed.", COLOR_HIGHLIGHT))
        print(style(f"Try manually: {sys.executable or 'python3'} -m pip install -r {requirements_path}", STYLE_BOLD))
        print(style(f"Or: {sys.executable or 'python3'} -m pip install --break-system-packages -r {requirements_path}", STYLE_BOLD))
        return False

    still_missing = missing_python_modules(RUNTIME_REQUIRED_PY_MODULES)
    if still_missing:
        print(color_text(f"Runtime Python modules still missing after install: {', '.join(still_missing)}", COLOR_HIGHLIGHT))
        return False

    print(color_text("Runtime Python dependencies are ready.\n", COLOR_SUCCESS))
    return True


def report_tool_group(title: str, tools: List[str]) -> List[str]:
    missing: List[str] = []
    print(style(title, STYLE_BOLD))
    for tool in tools:
        if tool_exists(tool):
            status = color_text("OK", COLOR_SUCCESS)
        else:
            status = color_text("missing", COLOR_ERROR)
            missing.append(tool)
        print(f"- {tool.ljust(12)} {status}")
    print()
    return missing


def report_dependencies() -> Tuple[List[str], List[str]]:
    print_banner()
    print(style("Dependency check:", STYLE_BOLD))
    print()

    missing_required = report_tool_group("Required tools:", REQUIRED_TOOLS)
    missing_recommended = report_tool_group(
        "Recommended tools (full feature coverage):",
        RECOMMENDED_TOOLS,
    )
    return missing_required, missing_recommended


def ensure_dependencies(is_root: bool) -> None:
    missing_required, missing_recommended = report_dependencies()
    if not missing_required and not missing_recommended:
        print(color_text("All required and recommended tools are available.\n", COLOR_SUCCESS))
        return

    if not is_root:
        if missing_required:
            print(color_text("Run as root to allow automatic installation of missing required tools.\n", COLOR_HIGHLIGHT))
        if missing_recommended:
            print(color_text("Recommended tools are missing; some optional module features may be unavailable.\n", COLOR_HIGHLIGHT))
        return

    installed_any = False

    if missing_required:
        if prompt_yes_no("Install missing required tools now? [Y/n]: "):
            installed = install_missing_tools(missing_required)
            if installed:
                installed_any = True
            else:
                print(color_text("Could not install all required tools automatically. Please handle manually.\n", COLOR_HIGHLIGHT))
        else:
            print(color_text("Proceeding without required tools may lead to runtime failures.\n", COLOR_HIGHLIGHT))

    if missing_recommended:
        if prompt_yes_no("Install missing recommended tools for full module coverage? [Y/n]: "):
            installed = install_missing_tools(missing_recommended)
            if installed:
                installed_any = True
            else:
                print(color_text("Could not install all recommended tools automatically.\n", COLOR_HIGHLIGHT))

    if installed_any:
        final_required, final_recommended = report_dependencies()
        if not final_required:
            print(color_text("Required tools check passed.\n", COLOR_SUCCESS))
        if final_recommended:
            print(color_text("Some recommended tools are still missing.\n", COLOR_HIGHLIGHT))


def script_path(filename: str) -> str:
    return os.path.join(base_dir(), filename)


def print_header(
    title: str,
    menu: Dict[str, Dict[str, str]],
) -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    print(style(title, STYLE_BOLD))
    print()
    for key, meta in menu.items():
        if meta.get("separator"):
            name = meta.get("name", "")
            if name:
                print(f"  {color_text(name, COLOR_DIM)}")
            else:
                print()
            continue
        icon = meta.get("icon", "")
        icon_part = f"{icon} " if icon else ""
        label = f"[{key}] {icon_part}{meta['name']}"
        color = COLOR_DIM if meta.get("disabled") else meta.get("color", COLOR_HIGHLIGHT)
        print(f"  {color_text(label, color)}")
    print()


def run_child(script_file: str, args: Optional[List[str]] = None) -> None:
    abs_path = script_path(script_file)
    if not os.path.isfile(abs_path):
        print(color_text(f"File not found: {abs_path}", COLOR_HIGHLIGHT))
        return

    cmd = [sys.executable or "python3", abs_path]
    if args:
        cmd.extend(args)
    print(style(f"Starting {script_file}...\n", STYLE_BOLD))

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        # Child should receive Ctrl+C too; return cleanly to launcher.
        pass
    print(style("\nDone. Press Enter to return to the menu.", COLOR_SUCCESS, STYLE_BOLD))
    try:
        input()
    except EOFError:
        pass


def attacks_menu() -> None:
    while True:
        print_header("Attacks:", ATTACKS_MENU)
        choice = input(style("Your choice (0-9): ", STYLE_BOLD)).strip()

        if choice not in ATTACKS_MENU or ATTACKS_MENU[choice].get("separator"):
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "0":
            break

        if ATTACKS_MENU[choice].get("disabled"):
            print(color_text("Coming soon.", COLOR_HIGHLIGHT))
            continue

        extra_args = ATTACKS_MENU[choice].get("args")
        if isinstance(extra_args, list):
            run_child(ATTACKS_MENU[choice]["file"], extra_args)
        else:
            run_child(ATTACKS_MENU[choice]["file"])


def main() -> None:
    is_root = os.geteuid() == 0
    ensure_dependencies(is_root)

    if not is_root:
        print(color_text("This launcher must be run as root.", COLOR_HIGHLIGHT))
        sys.exit(1)

    if not ensure_runtime_python_dependencies():
        print(color_text("Some modules may fail without runtime Python dependencies.", COLOR_HIGHLIGHT))

    while True:
        print_header("Main menu:", MAIN_MENU)
        choice = input(style("Your choice (0-3): ", STYLE_BOLD)).strip()

        if choice not in MAIN_MENU:
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "0":
            print()
            print(style("Mission complete!", COLOR_SUCCESS, STYLE_BOLD))
            print(style("No packets were emotionally harmed.", COLOR_HIGHLIGHT, STYLE_BOLD))
            print()
            break

        if choice == "1":
            run_child(RECON_SCRIPT)
            continue

        if choice == "2":
            attacks_menu()
            continue

        if choice == "3":
            run_child(BLUETOOTH_SCRIPT)
            continue


if __name__ == "__main__":
    main()
