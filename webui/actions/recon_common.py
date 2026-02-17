#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules import recon  # noqa: E402
from webui.ap_mode import detect_builtin_wireless_interface, list_wireless_interfaces  # noqa: E402


def ensure_runtime_requirements() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Recon Web UI actions must run as root.")

    required_tools = ("iw", "ip", "ethtool", "airodump-ng")
    missing = [
        tool
        for tool in required_tools
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode != 0
    ]
    if missing:
        raise RuntimeError(f"Missing required tools: {', '.join(missing)}")


def parse_channels(raw: str) -> List[int]:
    if not raw.strip():
        return list(recon.DEFAULT_MONITOR_CHANNELS)

    channels: List[int] = []
    for chunk in raw.split(","):
        value = chunk.strip()
        if not value:
            continue
        try:
            channel = int(value)
        except ValueError:
            raise RuntimeError(f"Invalid channel value: '{value}'") from None
        if channel not in channels:
            channels.append(channel)
    if not channels:
        raise RuntimeError("Channel list cannot be empty.")
    return channels


def resolve_tool_interface(requested: str, allow_builtin: bool = False) -> str:
    wireless = set(list_wireless_interfaces())
    all_interfaces = [iface for iface in recon.list_network_interfaces() if iface in wireless]
    if not all_interfaces:
        raise RuntimeError("No wireless interfaces detected.")

    try:
        builtin_iface = detect_builtin_wireless_interface()
    except RuntimeError:
        builtin_iface = ""

    if requested and requested != "auto":
        if requested not in all_interfaces:
            raise RuntimeError(f"Interface '{requested}' is not available.")
        if builtin_iface and requested == builtin_iface and not allow_builtin:
            raise RuntimeError(
                f"Interface '{requested}' is reserved for AP/Web UI communication. "
                "Use an external adapter (e.g., wlan1/wlan2)."
            )
        return requested

    tool_interfaces = [iface for iface in all_interfaces if iface != builtin_iface]
    if tool_interfaces:
        # Prefer standard wlan naming order.
        tool_interfaces.sort(key=lambda name: (0 if name.startswith("wlan") else 1, name))
        return tool_interfaces[0]

    if allow_builtin and builtin_iface:
        return builtin_iface
    raise RuntimeError(
        "No external wireless interface available for tools. "
        "Built-in adapter is reserved for AP/Web UI."
    )


def enable_monitor_mode(interface: str) -> tuple[Optional[str], bool]:
    original_mode = recon.get_interface_mode(interface)
    if original_mode == "monitor":
        return original_mode, False
    if not recon.set_interface_type(interface, "monitor"):
        raise RuntimeError(f"Failed to enable monitor mode on {interface}.")
    recon.wait_for_monitor_settle(interface)
    return original_mode, True


def restore_interface_mode(
    interface: str,
    original_mode: Optional[str],
    changed: bool,
    keep_monitor: bool,
) -> None:
    if keep_monitor:
        return
    if changed and original_mode and original_mode != "monitor":
        recon.restore_managed_mode(interface)


def serialize_access_points(
    aps: Dict[str, recon.AccessPoint],
    vendors: Dict[str, str],
) -> List[Dict[str, object]]:
    ordered = sorted(
        aps.values(),
        key=lambda ap: ap.signal if ap.signal is not None else -1,
        reverse=True,
    )
    payload: List[Dict[str, object]] = []
    for ap in ordered:
        vendor = recon.lookup_vendor(ap.bssid, vendors)
        payload.append(
            {
                "ssid": ap.ssid,
                "bssid": ap.bssid,
                "channel": ap.channel,
                "encryption": ap.encryption,
                "rssi": ap.rssi,
                "signal": ap.signal,
                "client_count": len(ap.clients),
                "clients": sorted(ap.clients),
                "vendor": vendor,
            }
        )
    return payload
