"""Small-screen Pi diagnostics and NetworkManager actions.

This script runs through runner.py so input/getpass are handled by the LCD.
Only fixed commands are executed; menu input never reaches a shell.
"""

from __future__ import annotations

import argparse
import getpass
import shlex
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Device:
    name: str
    kind: str
    state: str


@dataclass(frozen=True)
class Network:
    ssid: str
    signal: str
    security: str


@dataclass(frozen=True)
class Profile:
    uuid: str
    kind: str
    name: str


def command(*args: str, timeout: int = 30) -> str:
    visible_args = list(args)
    for index, value in enumerate(visible_args[:-1]):
        if value == "password":
            visible_args[index + 1] = "********"
    print("$ " + shlex.join(visible_args), flush=True)
    try:
        result = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing command: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Timed out: {args[0]}") from exc
    output = (result.stdout + result.stderr).strip()
    if result.returncode:
        raise RuntimeError(output or f"{args[0]} exited with {result.returncode}")
    return output


def choose(title: str, labels: list[str], *, allow_cancel: bool = True) -> int | None:
    if not labels:
        print("No entries found.")
        return None
    print(title)
    for index, label in enumerate(labels[:99], 1):
        print(f"  [{index}] {label}")
    if allow_cancel:
        print("  [0] Cancel")
    while True:
        value = input("Select option: ").strip()
        if allow_cancel and value == "0":
            return None
        if value.isdigit() and 1 <= int(value) <= min(len(labels), 99):
            return int(value) - 1
        print("Choose a listed number.")


def devices(kind: str | None = None) -> list[Device]:
    output = command("nmcli", "-t", "-e", "no", "-f", "DEVICE,TYPE,STATE", "device", "status")
    found = []
    for line in output.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] and (kind is None or parts[1] == kind):
            found.append(Device(*parts))
    return found


def choose_device(kind: str | None = None) -> Device | None:
    available = [device for device in devices(kind) if device.kind in {"wifi", "ethernet"}]
    index = choose("Network interfaces:", [f"{item.name} {item.kind} {item.state}" for item in available])
    return available[index] if index is not None else None


def wifi_networks(interface: str) -> list[Network]:
    output = command(
        "nmcli", "-t", "-e", "no", "-f", "SSID,SIGNAL,SECURITY",
        "device", "wifi", "list", "--rescan", "yes", "ifname", interface,
        timeout=45,
    )
    strongest: dict[str, Network] = {}
    for line in output.splitlines():
        parts = line.rsplit(":", 2)
        if len(parts) != 3 or not parts[0]:
            continue
        network = Network(*parts)
        if network.ssid not in strongest or int(network.signal or 0) > int(strongest[network.ssid].signal or 0):
            strongest[network.ssid] = network
    return sorted(strongest.values(), key=lambda item: int(item.signal or 0), reverse=True)


def profiles() -> list[Profile]:
    output = command("nmcli", "-t", "-e", "no", "-f", "UUID,TYPE,NAME", "connection", "show")
    found = []
    for line in output.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0]:
            found.append(Profile(*parts))
    return found


def show_usb() -> None:
    print(command("lsusb") or "No USB devices reported.")


def show_interfaces() -> None:
    found = devices()
    if not found:
        print("NetworkManager reported no interfaces.")
    for index, device in enumerate(found, 1):
        print(f"{index}) {device.name} - {device.kind} / {device.state}")
    print("\nIP addresses:")
    print(command("ip", "-br", "address"))


def show_wifi() -> None:
    device = choose_device("wifi")
    if device is None:
        return
    networks = wifi_networks(device.name)
    if not networks:
        print("No visible Wi-Fi networks.")
    for index, network in enumerate(networks, 1):
        print(f"{index}) {network.ssid} - {network.signal}%  {network.security or 'open'}")


def connect_wifi() -> None:
    device = choose_device("wifi")
    if device is None:
        return
    networks = wifi_networks(device.name)
    labels = [f"{item.ssid} {item.signal}% {item.security or 'open'}" for item in networks[:98]]
    labels.append("Type SSID manually")
    selection = choose("Wi-Fi networks:", labels)
    if selection is None:
        return
    if selection == len(labels) - 1:
        ssid = input("SSID: ").strip()
        if not ssid:
            print("SSID cannot be empty.")
            return
        password = getpass.getpass("Password (empty=open): ")
    else:
        network = networks[selection]
        ssid = network.ssid
        if "802.1X" in network.security or "EAP" in network.security:
            print("Enterprise Wi-Fi: use SSH sudo nmtui.")
            return
        password = getpass.getpass("Password: ") if network.security not in {"", "--"} else ""
    args = ["nmcli", "--wait", "60", "device", "wifi", "connect", ssid]
    if password:
        args.extend(("password", password))
    args.extend(("ifname", device.name))
    print(f"Connecting {device.name} to {ssid}...")
    print(command(*args, timeout=70))


def show_profiles() -> None:
    saved = profiles()
    if not saved:
        print("No saved connections.")
    for index, profile in enumerate(saved, 1):
        print(f"{index}) {profile.name} - {profile.kind}")


def activate_profile() -> None:
    saved = profiles()
    index = choose("Saved connections:", [f"{item.name} {item.kind}" for item in saved])
    if index is None:
        return
    profile = saved[index]
    kind = "wifi" if profile.kind in {"wifi", "802-11-wireless"} else "ethernet" if profile.kind in {"ethernet", "802-3-ethernet"} else None
    args = ["nmcli", "--wait", "60", "connection", "up", "uuid", profile.uuid]
    if kind:
        device = choose_device(kind)
        if device is None:
            return
        args.extend(("ifname", device.name))
    print(f"Activating {profile.name}...")
    print(command(*args, timeout=70))


def disconnect_device() -> None:
    device = choose_device()
    if device is None:
        return
    print(f"Disconnect {device.name}? SSH may drop.")
    answer = choose("Confirm:", ["Yes, disconnect", "No, cancel"], allow_cancel=False)
    if answer == 0:
        print(command("nmcli", "device", "down", device.name, timeout=20))


ACTIONS = {
    "usb": show_usb,
    "interfaces": show_interfaces,
    "wifi-scan": show_wifi,
    "wifi-connect": connect_wifi,
    "profiles": show_profiles,
    "activate": activate_profile,
    "disconnect": disconnect_device,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="SwissKnifOS Pi commands")
    parser.add_argument("action", choices=ACTIONS)
    args = parser.parse_args()
    try:
        ACTIONS[args.action]()
    except (RuntimeError, ValueError) as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
