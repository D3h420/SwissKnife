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
import socket
import time
import signal
import secrets
import importlib.util
from dataclasses import dataclass
from typing import Dict, List, Optional, TextIO

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
    "1": {"name": "Recon", "action": "recon", "icon": "🛰️"},
    "2": {"name": "Attacks", "action": "attacks", "icon": "⚔️"},
    "3": {"name": "Bluetooth", "action": "bluetooth", "icon": "📶"},
    "4": {"name": "Exit", "action": "exit", "icon": "🚪"},
}

ATTACKS_MENU: Dict[str, Dict[str, str]] = {
    "basic": {"name": "-BASIC-", "separator": True},
    "1": {"name": "Deauth", "file": os.path.join("modules", "deauth.py")},
    "2": {"name": "Portal", "file": os.path.join("modules", "portal.py")},
    "3": {"name": "Evil Twin", "file": os.path.join("modules", "twins.py")},
    "4": {"name": "Handshaker", "file": os.path.join("modules", "handshaker.py")},
    "5": {"name": "SEA Overflow (Jan nedded here).", "file": "", "disabled": True},
    "6": {"name": "Karma (under construction)", "file": "", "disabled": True},
    "spacer_after_basic": {"name": "", "separator": True},
    "inside": {"name": "-INSIDE-", "separator": True},
    "7": {"name": "ARP scan", "file": os.path.join("modules", "arp_scanner.py")},
    "8": {"name": "IP.CAM finder", "file": os.path.join("modules", "ipcam_finder.py")},
    "spacer": {"name": "", "separator": True},
    "9": {"name": "Back", "file": ""},
}

RECON_SCRIPT = os.path.join("modules", "recon.py")
BLUETOOTH_SCRIPT = os.path.join("modules", "bluetooth.py")
WEBUI_REQUIREMENTS = os.path.join("webui", "requirements.txt")
WEBUI_PORT = 8000
WEBUI_HOST = "0.0.0.0"
WEBUI_AP_INTERFACE = "builtin"
WEBUI_AP_IP = "10.10.0.1"
WEBUI_TOKEN_HEADER = "X-SwissKnife-Token"
WEBUI_LOG_FILE = os.path.join("webui", "webui_server.log")
WEBUI_TOKEN_FILE = os.path.join("webui", ".webui_token")
WEBUI_LAUNCHER_PID_ENV = "SWISSKNIFE_LAUNCHER_PID"
WEBUI_REQUIRED_PY_MODULES: List[str] = [
    "fastapi",
    "uvicorn",
    "pydantic",
]

REQUIRED_TOOLS: List[str] = [
    "iw",
    "ip",
    "ethtool",
    "aireplay-ng",
    "airodump-ng",
    "bluetoothctl",
    "btmgmt",
    "hostapd",
    "dnsmasq",
    "iptables",
]

PACKAGE_MAPS = {
    "apt": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
    },
    "apt-get": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
    },
    "dnf": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute",
    },
    "yum": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute",
    },
    "pacman": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
    },
    "zypper": {
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "bluetoothctl": "bluez",
        "btmgmt": "bluez",
        "ip": "iproute2",
    },
}


@dataclass
class WebUIProcess:
    process: subprocess.Popen
    token: str
    log_handle: TextIO
    log_path: str
    token_path: str
    token_created: bool
    token_persistent: bool


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


def install_webui_python_dependencies(requirements_path: str) -> bool:
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


def ensure_webui_python_dependencies() -> bool:
    missing = missing_python_modules(WEBUI_REQUIRED_PY_MODULES)
    if not missing:
        return True

    print(color_text(f"Missing Python modules for Web UI: {', '.join(missing)}", COLOR_HIGHLIGHT))
    requirements_path = script_path(WEBUI_REQUIREMENTS)
    if not os.path.isfile(requirements_path):
        print(color_text(f"Requirements file not found: {requirements_path}", COLOR_HIGHLIGHT))
        return False

    if not pip_available():
        print(color_text("pip is not available for this Python interpreter.", COLOR_HIGHLIGHT))
        print(style(f"Install manually: {sys.executable or 'python3'} -m ensurepip --upgrade", STYLE_BOLD))
        return False

    if not prompt_yes_no("Install Web UI Python dependencies now? [Y/n]: "):
        print(style(f"Install manually: {sys.executable or 'python3'} -m pip install -r {requirements_path}", STYLE_BOLD))
        print(style(f"If needed on Debian/Ubuntu: {sys.executable or 'python3'} -m pip install --break-system-packages -r {requirements_path}", STYLE_BOLD))
        return False

    if not install_webui_python_dependencies(requirements_path):
        print(color_text("Automatic Python dependency installation failed.", COLOR_HIGHLIGHT))
        print(style(f"Try manually: {sys.executable or 'python3'} -m pip install -r {requirements_path}", STYLE_BOLD))
        print(style(f"Or: {sys.executable or 'python3'} -m pip install --break-system-packages -r {requirements_path}", STYLE_BOLD))
        return False

    still_missing = missing_python_modules(WEBUI_REQUIRED_PY_MODULES)
    if still_missing:
        print(color_text(f"Web UI modules still missing after install: {', '.join(still_missing)}", COLOR_HIGHLIGHT))
        return False

    print(color_text("Web UI Python dependencies are ready.\n", COLOR_SUCCESS))
    return True


def report_dependencies() -> List[str]:
    missing = []
    print_banner()
    print(style("Dependency check:", STYLE_BOLD))

    for tool in REQUIRED_TOOLS:
        if tool_exists(tool):
            status = color_text("OK", COLOR_SUCCESS)
        else:
            status = color_text("missing", COLOR_ERROR)
            missing.append(tool)
        print(f"- {tool.ljust(12)} {status}")

    print()
    return missing


def ensure_dependencies(is_root: bool) -> None:
    missing = report_dependencies()
    if not missing:
        print(color_text("All required tools are available.\n", COLOR_SUCCESS))
        return

    if not is_root:
        print(color_text("Run as root to allow automatic installation of missing tools.\n", COLOR_HIGHLIGHT))
        return

    if not prompt_yes_no("Install missing tools now? [Y/n]: "):
        print(color_text("Proceeding without installation may lead to runtime failures.\n", COLOR_HIGHLIGHT))
        return

    installed = install_missing_tools(missing)
    if installed:
        report_dependencies()
    else:
        print(color_text("Could not install all tools automatically. Please handle manually.\n", COLOR_HIGHLIGHT))


def script_path(filename: str) -> str:
    return os.path.join(base_dir(), filename)


def detect_primary_ipv4() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))
            ip_addr = sock.getsockname()[0]
            if ip_addr and not ip_addr.startswith("127."):
                return ip_addr
    except OSError:
        pass

    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if "inet" in parts:
                    index = parts.index("inet")
                    if index + 1 < len(parts):
                        return parts[index + 1].split("/", 1)[0]
    except Exception:
        pass
    return None


def webui_hint_line(port: int = WEBUI_PORT) -> str:
    ip_addr = detect_primary_ipv4() or "<device-ip>"
    hostname = socket.gethostname().strip() or "swissknife"
    local_host = hostname if hostname.endswith(".local") else f"{hostname}.local"
    return (
        f"Web UI AP: http://{WEBUI_AP_IP}:{port}  |  "
        f"LAN: http://{ip_addr}:{port}  |  http://{local_host}:{port}"
    )


def read_file_tail(path: str, max_lines: int = 20) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return "(log unavailable)"
    if not lines:
        return "(no log output)"
    return "".join(lines[-max_lines:]).strip() or "(no log output)"


def stop_background_process(process: Optional[subprocess.Popen]) -> None:
    if not process or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except Exception:
        try:
            process.terminate()
        except Exception:
            return
    try:
        process.wait(timeout=2.5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except Exception:
        try:
            process.kill()
        except Exception:
            return
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass


def _read_persistent_webui_token(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            token = handle.read().strip()
    except OSError:
        return ""

    if len(token) < 16 or any(char.isspace() for char in token):
        return ""
    return token


def _write_persistent_webui_token(path: str, token: str) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        return False
    return True


def load_or_create_webui_token() -> tuple[str, str, bool, bool]:
    token_path = script_path(WEBUI_TOKEN_FILE)
    existing = _read_persistent_webui_token(token_path)
    if existing:
        return existing, token_path, False, True

    generated = secrets.token_urlsafe(20)
    if _write_persistent_webui_token(token_path, generated):
        return generated, token_path, True, True
    return generated, token_path, True, False


def start_webui_background() -> Optional[WebUIProcess]:
    token, token_path, token_created, token_persistent = load_or_create_webui_token()
    log_path = script_path(WEBUI_LOG_FILE)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log_handle = open(log_path, "w", encoding="utf-8")
    env = os.environ.copy()
    env[WEBUI_LAUNCHER_PID_ENV] = str(os.getpid())
    cmd = [
        sys.executable or "python3",
        "-m",
        "webui.server",
        "--host",
        WEBUI_HOST,
        "--port",
        str(WEBUI_PORT),
        "--ap-interface",
        WEBUI_AP_INTERFACE,
        "--ap-ip",
        WEBUI_AP_IP,
        "--token",
        token,
    ]
    process: Optional[subprocess.Popen] = None
    try:
        process = subprocess.Popen(
            cmd,
            cwd=base_dir(),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            env=env,
        )
        time.sleep(1.4)
        if process.poll() is not None:
            log_tail = read_file_tail(log_path)
            print(color_text("Web UI failed to start in background.", COLOR_HIGHLIGHT))
            print(color_text(f"Log file: {log_path}", COLOR_DIM))
            if log_tail:
                print(color_text(log_tail, COLOR_DIM))
            log_handle.close()
            return None
        return WebUIProcess(
            process=process,
            token=token,
            log_handle=log_handle,
            log_path=log_path,
            token_path=token_path,
            token_created=token_created,
            token_persistent=token_persistent,
        )
    except OSError as exc:
        if process and process.poll() is None:
            stop_background_process(process)
        log_handle.close()
        print(color_text(f"Failed to launch Web UI background process: {exc}", COLOR_HIGHLIGHT))
        return None


def stop_webui_background(service: Optional[WebUIProcess]) -> None:
    if not service:
        return
    stop_background_process(service.process)
    try:
        service.log_handle.close()
    except Exception:
        pass


def webui_status_line(service: Optional[WebUIProcess]) -> str:
    if not service:
        return f"Web UI autostart unavailable (check {script_path(WEBUI_LOG_FILE)})"
    if service.process.poll() is not None:
        return f"Web UI stopped (check {service.log_path})"
    if service.token_created and service.token_persistent:
        return (
            f"Web UI token saved to {service.token_path} "
            f"({WEBUI_TOKEN_HEADER}): {service.token}"
        )
    if service.token_persistent:
        return (
            f"Web UI token loaded from {service.token_path} "
            "(browser remembers it after first login)"
        )
    return (
        f"Web UI token ({WEBUI_TOKEN_HEADER}, ephemeral): {service.token}"
    )


def print_header(
    title: str,
    menu: Dict[str, Dict[str, str]],
    show_webui_hint: bool = False,
    webui_status: str = "",
) -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    if show_webui_hint:
        print(color_text(webui_hint_line(), COLOR_DIM))
        if webui_status:
            print(color_text(webui_status, COLOR_DIM))
        print()
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
    print(style("\nDone. Press Enter to return to the menu.", STYLE_BOLD))
    try:
        input()
    except EOFError:
        pass


def attacks_menu() -> None:
    while True:
        print_header("Attacks:", ATTACKS_MENU)
        choice = input(style("Your choice (1-9): ", STYLE_BOLD)).strip()

        if choice not in ATTACKS_MENU or ATTACKS_MENU[choice].get("separator"):
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "9":
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

    webui_service: Optional[WebUIProcess] = None
    if ensure_webui_python_dependencies():
        webui_service = start_webui_background()
    else:
        print(color_text("Web UI autostart skipped (missing Python dependencies).", COLOR_HIGHLIGHT))

    try:
        while True:
            if webui_service and webui_service.process.poll() is not None:
                print(color_text("Web UI stopped unexpectedly. Restarting background service...", COLOR_HIGHLIGHT))
                stop_webui_background(webui_service)
                webui_service = start_webui_background()

            print_header(
                "Main menu:",
                MAIN_MENU,
                show_webui_hint=True,
                webui_status=webui_status_line(webui_service),
            )
            choice = input(style("Your choice (1-4): ", STYLE_BOLD)).strip()

            if choice not in MAIN_MENU:
                print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
                continue

            if choice == "4":
                print()
                print(style("✅ Mission complete!", COLOR_SUCCESS, STYLE_BOLD))
                print(style("💚 no packets were emotionally harmed", COLOR_HIGHLIGHT, STYLE_BOLD))
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
    finally:
        stop_webui_background(webui_service)


if __name__ == "__main__":
    main()
