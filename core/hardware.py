"""Read-only hardware inventory shared by graphical front ends."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .wifi_iface import get_interface_chipset, get_interface_mode, list_network_interfaces, list_wireless_interfaces


def _command(*args: str) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout if result.returncode == 0 else ""


@dataclass(frozen=True)
class WiFiAdapter:
    name: str
    driver: str
    mode: str
    usb: bool
    monitor_supported: bool | None


@dataclass(frozen=True)
class HardwareSnapshot:
    interfaces: tuple[str, ...]
    wifi: tuple[WiFiAdapter, ...]
    usb: tuple[str, ...]
    gps_ports: tuple[str, ...]
    default_route: str
    is_root: bool
    tools: frozenset[str]


TOOLS = ("iw", "ip", "ethtool", "ping", "arp-scan", "nmcli", "lsusb", "stty", "airodump-ng", "aireplay-ng", "mdk4", "hostapd", "dnsmasq", "iptables", "bully")


def _monitor_support(interface: str) -> bool | None:
    info = _command("iw", "dev", interface, "info")
    match = re.search(r"\bwiphy\s+(\d+)\b", info)
    if not match:
        return None
    phy = _command("iw", "phy", f"phy{match.group(1)}", "info")
    if not phy:
        return None
    modes = phy.split("Supported interface modes:", 1)
    if len(modes) < 2:
        return None
    return bool(re.search(r"^\s*\*\s*monitor\s*$", modes[1].split("Band 1:", 1)[0], re.MULTILINE))


def _usb_devices() -> tuple[str, ...]:
    devices: list[str] = []
    for device in Path("/sys/bus/usb/devices").glob("*"):
        try:
            product = (device / "product").read_text(errors="replace").strip()
            maker = (device / "manufacturer").read_text(errors="replace").strip() if (device / "manufacturer").exists() else ""
        except OSError:
            continue
        if product:
            devices.append(f"{maker} {product}".strip())
    return tuple(sorted(set(devices)))


def detect_hardware() -> HardwareSnapshot:
    names = tuple(list_network_interfaces())
    wireless = list_wireless_interfaces()
    if not wireless:
        wireless = [name for name in names if (Path("/sys/class/net") / name / "wireless").exists()]
    wifi: list[WiFiAdapter] = []
    for name in wireless:
        path = Path("/sys/class/net") / name / "device"
        try:
            usb = "usb" in str(path.resolve()).lower()
        except OSError:
            usb = False
        wifi.append(WiFiAdapter(name, get_interface_chipset(name), get_interface_mode(name) or "unknown", usb, _monitor_support(name)))
    route = _command("ip", "route", "show", "default")
    route_match = re.search(r"\bdev\s+(\S+)", route)
    gps_ports = tuple(sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")))
    return HardwareSnapshot(
        interfaces=names,
        wifi=tuple(wifi),
        usb=_usb_devices(),
        gps_ports=gps_ports,
        default_route=route_match.group(1) if route_match else "",
        is_root=os.geteuid() == 0,
        tools=frozenset(tool for tool in TOOLS if shutil.which(tool)),
    )
