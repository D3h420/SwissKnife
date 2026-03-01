#!/usr/bin/env python3

import os
import re
import sys
import time
import signal
import threading
import subprocess
import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

SCAN_REFRESH_SECONDS = 0.8

ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
BTCTL_EVENT_PATTERN = re.compile(r"^(?:\[[A-Z]+\]\s+)?Device\s+([0-9A-Fa-f:]{17})(?:\s+(.*))?$")
DEVICE_LIST_PATTERN = re.compile(r"^Device\s+([0-9A-Fa-f:]{17})\s+(.+)$")
CONTROLLER_LIST_PATTERN = re.compile(r"^Controller\s+([0-9A-Fa-f:]{17})\s+(.+)$")
MAC_PATTERN = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
RSSI_PATTERN = re.compile(r"RSSI:\s*(-?\d+)|rssi\s*(-?\d+)")
HCI_INTERFACE_PATTERN = re.compile(r"^(hci\d+):")
BD_ADDRESS_PATTERN = re.compile(r"BD Address:\s*([0-9A-Fa-f:]{17})")
MAC_ONLY_PATTERN = re.compile(r"^[0-9A-Fa-f:]{17}$")

CONTROLLER_CACHE: Dict[str, str] = {}


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


def run_command(
    args: List[str],
    capture_output: bool = False,
    timeout: Optional[float] = None,
    input_text: Optional[str] = None,
) -> subprocess.CompletedProcess:
    kwargs = {"text": True, "check": False}
    if capture_output:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    else:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    if timeout is not None:
        kwargs["timeout"] = timeout
    if input_text is not None:
        kwargs["input"] = input_text

    try:
        return subprocess.run(args, **kwargs)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args=args,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )


def run_bluetoothctl(
    args: List[str],
    capture_output: bool = False,
    timeout: Optional[float] = None,
    controller: Optional[str] = None,
) -> subprocess.CompletedProcess:
    selected = resolve_controller_address(controller)
    if not selected:
        return run_command(["bluetoothctl", *args], capture_output=capture_output, timeout=timeout)

    script_lines = [
        f"select {selected}",
        " ".join(args),
        "quit",
    ]
    script = "\n".join(script_lines) + "\n"
    return run_command(
        ["bluetoothctl"],
        capture_output=capture_output,
        timeout=timeout,
        input_text=script,
    )


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_PATTERN.sub("", text)


def extract_rssi(text: str) -> Optional[int]:
    match = RSSI_PATTERN.search(text)
    if not match:
        return None
    raw = match.group(1) if match.group(1) is not None else match.group(2)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def normalize_mac(mac: str) -> str:
    return mac.strip().upper()


def looks_like_mac(value: str) -> bool:
    return MAC_ONLY_PATTERN.fullmatch(value.strip()) is not None


def resolve_controller_address(controller: Optional[str]) -> Optional[str]:
    if not controller:
        return None

    token = controller.strip()
    if not token:
        return None

    if looks_like_mac(token):
        return normalize_mac(token)

    cached = CONTROLLER_CACHE.get(token)
    if cached:
        return cached

    if token.startswith("hci") and tool_exists("hciconfig"):
        details = run_command(["hciconfig", token], capture_output=True, timeout=2.0)
        if details.returncode == 0:
            for raw_line in details.stdout.splitlines():
                match = BD_ADDRESS_PATTERN.search(raw_line)
                if match:
                    address = normalize_mac(match.group(1))
                    CONTROLLER_CACHE[token] = address
                    return address
    return None


@dataclass
class BluetoothDevice:
    mac: str
    name: str = "<unknown>"
    rssi: Optional[int] = None
    last_seen: float = 0.0


class StreamingProcess:
    def __init__(self, cmd: List[str], on_line: Callable[[str], None]):
        self.cmd = cmd
        self.on_line = on_line
        self.process: Optional[subprocess.Popen] = None
        self.stop_event = threading.Event()
        self.reader_thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        try:
            self.process = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError):
            return False

        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        return True

    def _reader_loop(self) -> None:
        if not self.process or not self.process.stdout:
            return
        while not self.stop_event.is_set():
            line = self.process.stdout.readline()
            if line == "":
                if self.process.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            cleaned = strip_ansi(line.strip())
            if cleaned:
                self.on_line(cleaned)

    def stop(self) -> None:
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except Exception:
                self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except Exception:
                    self.process.kill()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1)


class BluetoothctlSession:
    def __init__(self, on_line: Callable[[str], None], controller: Optional[str] = None):
        self.on_line = on_line
        self.controller = controller
        self.process: Optional[subprocess.Popen] = None
        self.stop_event = threading.Event()
        self.reader_thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        try:
            self.process = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except (FileNotFoundError, OSError):
            return False

        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        selected = resolve_controller_address(self.controller)
        if selected:
            self.send(f"select {selected}")
        return True

    def _reader_loop(self) -> None:
        if not self.process or not self.process.stdout:
            return
        while not self.stop_event.is_set():
            line = self.process.stdout.readline()
            if line == "":
                if self.process.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            cleaned = strip_ansi(line.strip())
            if cleaned:
                self.on_line(cleaned)

    def send(self, command: str) -> None:
        if not self.process or not self.process.stdin:
            return
        try:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
        except Exception:
            pass

    def stop(self) -> None:
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            try:
                self.send("scan off")
                self.send("quit")
            except Exception:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1)


def ensure_interface_up(interface: str) -> None:
    if not interface.startswith("hci"):
        return
    if not tool_exists("hciconfig"):
        return
    run_command(["hciconfig", interface, "up"])
    run_command(["hciconfig", interface, "reset"])


def ensure_bluetooth_service(interface: str) -> None:
    if tool_exists("rfkill"):
        run_command(["rfkill", "unblock", "bluetooth"])

    if tool_exists("systemctl"):
        active = run_command(["systemctl", "is-active", "bluetooth"], capture_output=True)
        if active.stdout.strip() != "active":
            run_command(["systemctl", "start", "bluetooth"])

    ensure_interface_up(interface)
    run_bluetoothctl(["power", "on"], controller=interface)


def list_hci_interfaces() -> List[str]:
    if not tool_exists("hciconfig"):
        return list_btctl_controllers()
    result = run_command(["hciconfig"], capture_output=True)
    interfaces: List[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        match = HCI_INTERFACE_PATTERN.match(line)
        if match:
            interfaces.append(match.group(1))
    if interfaces:
        return interfaces
    return list_btctl_controllers()


def list_btctl_controllers() -> List[str]:
    if not tool_exists("bluetoothctl"):
        return []
    listed = run_bluetoothctl(["list"], capture_output=True, timeout=2.5)
    if listed.returncode != 0:
        return []

    controllers: List[str] = []
    for raw_line in listed.stdout.splitlines():
        line = raw_line.strip()
        match = CONTROLLER_LIST_PATTERN.match(line)
        if not match:
            continue
        controllers.append(match.group(1).upper())
    return controllers


def hci_index(interface: str) -> int:
    if interface.startswith("hci") and interface[3:].isdigit():
        return int(interface[3:])
    return 9999


def hci_device_path(interface: str) -> Optional[str]:
    path = os.path.join("/sys/class/bluetooth", interface, "device")
    if not os.path.exists(path):
        return None
    try:
        return os.path.realpath(path)
    except OSError:
        return None


def is_usb_controller(interface: str) -> bool:
    path = hci_device_path(interface)
    return bool(path and "/usb" in path.lower())


def controller_label(interface: str) -> str:
    if is_usb_controller(interface):
        return "USB adapter"
    if hci_device_path(interface):
        return "internal controller"
    return "controller"


def interface_display_name(interface: str) -> str:
    return f"{controller_label(interface)} ({interface})"


def select_hci_interface(interfaces: List[str]) -> str:
    if not interfaces:
        return "hci0"

    ranked = sorted(
        interfaces,
        key=lambda iface: (is_usb_controller(iface), hci_index(iface), iface),
    )
    selected = ranked[0]

    if len(ranked) > 1:
        logging.info("")
        logging.info(style("Bluetooth interface auto-selection:", STYLE_BOLD))
        for iface in ranked:
            selected_mark = " [selected]" if iface == selected else ""
            logging.info("  - %s (%s)%s", iface, controller_label(iface), selected_mark)
        if is_usb_controller(selected):
            logging.warning("No internal controller detected. Falling back to %s.", selected)

    return selected


def update_device(
    devices: Dict[str, BluetoothDevice],
    mac: str,
    name: Optional[str] = None,
    rssi: Optional[int] = None,
) -> None:
    now = time.time()
    key = normalize_mac(mac)
    device = devices.get(key)
    if device is None:
        device = BluetoothDevice(mac=key, last_seen=now)
        devices[key] = device
    else:
        device.last_seen = now

    if name:
        clean_name = name.strip()
        if clean_name and clean_name not in (
            "(random)",
            "(public)",
            "(not available)",
            "RSSI:",
        ):
            device.name = clean_name
    if rssi is not None:
        device.rssi = rssi


def parse_btctl_line(devices: Dict[str, BluetoothDevice], line: str) -> None:
    if "Device" not in line:
        return
    line = line.replace("[bluetooth]#", "").strip()
    match = BTCTL_EVENT_PATTERN.search(line)
    if not match:
        return

    mac = match.group(1)
    payload = (match.group(2) or "").strip()
    rssi = extract_rssi(payload) if payload else None
    if payload.startswith((
        "TxPower:",
        "ManufacturerData",
        "ServiceData",
        "UUID",
        "Class",
        "Address Type",
        "ServicesResolved",
        "Paired:",
        "Trusted:",
        "Blocked:",
        "Connected:",
        "LegacyPairing:",
        "Name:",
        "Alias:",
        "RSSI:",
    )):
        if payload.startswith(("Name:", "Alias:")):
            _, value = payload.split(":", 1)
            update_device(devices, mac, value.strip(), rssi)
        else:
            update_device(devices, mac, None, rssi)
        return

    update_device(devices, mac, payload if payload else None, rssi)


def parse_hcitool_line(devices: Dict[str, BluetoothDevice], line: str) -> None:
    match = MAC_PATTERN.search(line)
    if not match:
        return
    mac = match.group(1)
    rest = line.replace(mac, "", 1).strip()
    name = rest if rest else None
    update_device(devices, mac, name, None)


def run_periodic_hcitool_classic_scan(
    interface: str,
    stop_event: threading.Event,
    devices: Dict[str, BluetoothDevice],
    lock: threading.Lock,
) -> None:
    while not stop_event.is_set():
        result = run_command(
            ["hcitool", "-i", interface, "scan"],
            capture_output=True,
            timeout=12.0,
        )
        if result.returncode == 0:
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if not line or line.lower().startswith("scanning"):
                    continue
                with lock:
                    parse_hcitool_line(devices, line)

        # Sleep in short chunks so Ctrl+C stop is responsive.
        for _ in range(20):
            if stop_event.is_set():
                break
            time.sleep(0.25)


def parse_btmgmt_line(devices: Dict[str, BluetoothDevice], line: str) -> None:
    match = MAC_PATTERN.search(line)
    if not match:
        return
    mac = match.group(1)
    rssi = extract_rssi(line)

    name = None
    lower = line.lower()
    if "name " in lower:
        idx = lower.find("name ")
        if idx >= 0:
            name = line[idx + 5 :].strip()

    update_device(devices, mac, name, rssi)


def enrich_from_bluetoothctl(
    devices: Dict[str, BluetoothDevice],
    interface: str,
    per_cycle_limit: int = 20,
) -> None:
    listed = run_bluetoothctl(["devices"], capture_output=True, timeout=2.5, controller=interface)
    if listed.returncode != 0:
        return

    candidates: List[str] = []
    for raw_line in listed.stdout.splitlines():
        line = raw_line.strip()
        match = DEVICE_LIST_PATTERN.match(line)
        if not match:
            continue
        mac = normalize_mac(match.group(1))
        name = match.group(2).strip()
        update_device(devices, mac, name, None)
        candidates.append(mac)

    # Query detailed info for a limited number each cycle to populate RSSI reliably.
    for mac in candidates[:per_cycle_limit]:
        info = run_bluetoothctl(["info", mac], capture_output=True, timeout=2.0, controller=interface)
        if info.returncode != 0:
            continue

        name: Optional[str] = None
        rssi: Optional[int] = None
        for raw_line in info.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith(("Name:", "Alias:")):
                _, value = line.split(":", 1)
                value = value.strip()
                if value:
                    name = value
            if line.startswith("RSSI:"):
                rssi = extract_rssi(line)
        update_device(devices, mac, name, rssi)


def sorted_devices(devices: Dict[str, BluetoothDevice]) -> List[BluetoothDevice]:
    return sorted(
        devices.values(),
        key=lambda item: (
            item.rssi is None,
            -(item.rssi if item.rssi is not None else -1000),
            item.name.lower(),
            item.mac,
        ),
    )


def render_scan_live(
    devices: Dict[str, BluetoothDevice],
    started_at: float,
    backend_status: str,
) -> None:
    elapsed = int(time.time() - started_at)
    lines = [
        style("BT Scan (live)", STYLE_BOLD),
        f"Elapsed: {elapsed}s",
        f"Devices: {len(devices)}",
        f"Backends: {backend_status}",
        "Press Enter or Ctrl+C to stop.",
        "",
    ]

    ordered = sorted_devices(devices)
    if not ordered:
        lines.append(color_text("Scanning... no devices yet.", COLOR_WARNING))
    else:
        for index, device in enumerate(ordered, start=1):
            rssi = f"rssi {device.rssi} dBm" if device.rssi is not None else "rssi ?"
            label = f"{index}) {device.name} ({device.mac}) -"
            lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {rssi}")

    output = "\n".join(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


def install_stop_on_sigint(stop_event: threading.Event):
    previous = signal.getsignal(signal.SIGINT)

    def handler(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handler)
    return previous


def restore_signal(previous_handler) -> None:
    signal.signal(signal.SIGINT, previous_handler)


def scan_bt_devices_live(interface: str) -> List[BluetoothDevice]:
    ensure_bluetooth_service(interface)

    devices: Dict[str, BluetoothDevice] = {}
    lock = threading.Lock()
    stop_event = threading.Event()
    started_at = time.time()

    btctl = BluetoothctlSession(
        on_line=lambda line: _on_btctl_line(line, devices, lock),
        controller=interface,
    )

    backends: List[StreamingProcess] = []
    periodic_threads: List[threading.Thread] = []
    active_backend_names: List[str] = []

    previous_sigint = install_stop_on_sigint(stop_event)

    def wait_for_enter() -> None:
        try:
            input()
        except EOFError:
            pass
        stop_event.set()

    stopper = threading.Thread(target=wait_for_enter, daemon=True)

    try:
        if btctl.start():
            active_backend_names.append("bluetoothctl")
            btctl.send("power on")
            btctl.send("pairable on")
            btctl.send("discoverable on")
            btctl.send("scan on")
        else:
            logging.error("Failed to start bluetoothctl session.")
            return []

        if tool_exists("hcitool") and interface.startswith("hci"):
            ensure_interface_up(interface)
            lescan = StreamingProcess(
                ["hcitool", "-i", interface, "lescan", "--duplicates"],
                on_line=lambda line: _on_hcitool_line(line, devices, lock),
            )
            if lescan.start():
                backends.append(lescan)
                active_backend_names.append("hcitool")

            classic_thread = threading.Thread(
                target=run_periodic_hcitool_classic_scan,
                args=(interface, stop_event, devices, lock),
                daemon=True,
            )
            classic_thread.start()
            periodic_threads.append(classic_thread)
            active_backend_names.append("hcitool-classic")

        if tool_exists("btmgmt") and interface.startswith("hci"):
            btmgmt = StreamingProcess(
                ["btmgmt", "-i", interface, "find"],
                on_line=lambda line: _on_btmgmt_line(line, devices, lock),
            )
            if btmgmt.start():
                backends.append(btmgmt)
                active_backend_names.append("btmgmt")

        stopper.start()
        last_enrich = 0.0
        while not stop_event.is_set():
            now = time.time()
            if now - last_enrich > 2.5:
                with lock:
                    enrich_from_bluetoothctl(devices, interface)
                last_enrich = now

            with lock:
                snapshot = {k: BluetoothDevice(**vars(v)) for k, v in devices.items()}
            render_scan_live(snapshot, started_at, ", ".join(active_backend_names) or "none")
            time.sleep(SCAN_REFRESH_SECONDS)

    finally:
        stop_event.set()
        btctl.stop()
        for backend in backends:
            backend.stop()
        for thread in periodic_threads:
            if thread.is_alive():
                thread.join(timeout=0.2)
        if stopper.is_alive():
            stopper.join(timeout=0.2)
        restore_signal(previous_sigint)

    with lock:
        return sorted_devices(devices)


def _on_btctl_line(line: str, devices: Dict[str, BluetoothDevice], lock: threading.Lock) -> None:
    if not line:
        return
    with lock:
        parse_btctl_line(devices, line)


def _on_hcitool_line(line: str, devices: Dict[str, BluetoothDevice], lock: threading.Lock) -> None:
    if not line:
        return
    with lock:
        parse_hcitool_line(devices, line)


def _on_btmgmt_line(line: str, devices: Dict[str, BluetoothDevice], lock: threading.Lock) -> None:
    if not line:
        return
    with lock:
        parse_btmgmt_line(devices, line)


def scan_flow() -> None:
    interface = select_hci_interface(list_hci_interfaces())
    interface_label = interface_display_name(interface)

    logging.info("")
    input(
        f"{style('Press Enter', STYLE_BOLD)} to start live BT scan on {interface_label} "
        f"({style('Enter/Ctrl+C', STYLE_BOLD)} to stop)..."
    )

    devices = scan_bt_devices_live(interface)

    logging.info("")
    if not devices:
        logging.warning("No Bluetooth devices found.")
        logging.warning("If this is unexpected, verify: controller powered on, not rfkill-blocked, and BlueZ service active.")
    else:
        logging.info(style("Final discovered devices:", STYLE_BOLD))
        for index, device in enumerate(devices, start=1):
            rssi = f"rssi {device.rssi} dBm" if device.rssi is not None else "rssi ?"
            label = f"{index}) {device.name} ({device.mac}) -"
            logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), rssi)

    input(style("Press Enter to return.", STYLE_BOLD))


def menu_loop() -> None:
    while True:
        logging.info("")
        logging.info(style("Bluetooth menu:", STYLE_BOLD))
        logging.info("  %s", color_text("[1] Scan BT devices", COLOR_HIGHLIGHT))
        logging.info("  %s", color_text("[0] Back", COLOR_HIGHLIGHT))
        choice = input(style("Your choice (0-1): ", STYLE_BOLD)).strip()
        if choice == "1":
            scan_flow()
            continue
        if choice == "0":
            return
        logging.warning("Invalid choice.")


def main() -> None:
    logging.info(color_text("Bluetooth Toolkit", COLOR_HEADER))
    logging.info("Bluetooth discovery scan")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not tool_exists("bluetoothctl"):
        logging.error("Required tool 'bluetoothctl' not found!")
        sys.exit(1)

    menu_loop()


if __name__ == "__main__":
    main()
