#!/usr/bin/env python3
"""Shared helpers for Wi-Fi interface discovery and mode management."""

from __future__ import annotations

import subprocess
import time
from typing import List, Optional, Tuple


def list_network_interfaces() -> List[str]:
    interfaces: List[str] = []
    try:
        ip_link = subprocess.run(
            ["ip", "-o", "link", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return interfaces

    for line in ip_link.stdout.splitlines():
        if ": " not in line:
            continue
        name = line.split(": ", 1)[1].split(":", 1)[0]
        if name and name != "lo":
            interfaces.append(name)
    return interfaces


def list_wireless_interfaces() -> List[str]:
    try:
        result = subprocess.run(
            ["iw", "dev"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []

    if result.returncode != 0:
        return []

    interfaces: List[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Interface "):
            name = line.split("Interface", 1)[1].strip()
            if name:
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

    driver: Optional[str] = None
    bus_info: Optional[str] = None
    for line in result.stdout.splitlines():
        if line.startswith("driver:"):
            driver = line.split(":", 1)[1].strip()
        elif line.startswith("bus-info:"):
            bus_info = line.split(":", 1)[1].strip()

    if driver and bus_info:
        return f"{driver} ({bus_info})"
    if driver:
        return driver
    return "unknown"


def get_interface_mode(
    interface: str,
    *,
    fallback_iwconfig: bool = True,
    infer_monitor_suffix: bool = False,
) -> Optional[str]:
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        result = None

    if result is not None and result.returncode == 0:
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("type "):
                mode = line.split("type", 1)[1].strip().lower()
                if mode:
                    return mode

    if fallback_iwconfig:
        try:
            iwconfig_result = subprocess.run(
                ["iwconfig", interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            iwconfig_result = None

        if iwconfig_result is not None and iwconfig_result.returncode == 0:
            for raw_line in iwconfig_result.stdout.splitlines():
                if "Mode:" not in raw_line:
                    continue
                mode_part = raw_line.split("Mode:", 1)[1].strip()
                mode = mode_part.split()[0].strip().lower()
                if mode:
                    return mode

    if infer_monitor_suffix and interface.lower().endswith("mon"):
        return "monitor"
    return None


def is_interface_up(interface: str) -> bool:
    result = subprocess.run(
        ["ip", "link", "show", "dev", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False

    output = result.stdout
    if "state UP" in output:
        return True
    if "<" in output and ">" in output:
        flags = output.split("<", 1)[1].split(">", 1)[0]
        return "UP" in flags.split(",")
    return False


def wait_for_interface_mode(
    interface: str,
    target_mode: str,
    *,
    timeout_seconds: float = 6.0,
    poll_interval_seconds: float = 0.2,
    fallback_iwconfig: bool = True,
    infer_monitor_suffix: bool = False,
) -> bool:
    end_time = time.time() + max(0.5, timeout_seconds)
    target = (target_mode or "").strip().lower()
    while time.time() < end_time:
        current = get_interface_mode(
            interface,
            fallback_iwconfig=fallback_iwconfig,
            infer_monitor_suffix=infer_monitor_suffix,
        )
        if current == target:
            return True
        time.sleep(max(0.05, poll_interval_seconds))
    return False


def wait_for_interface_ready(
    interface: str,
    target_mode: str,
    *,
    timeout_seconds: float = 6.0,
    poll_interval_seconds: float = 0.2,
    fallback_iwconfig: bool = True,
    infer_monitor_suffix: bool = False,
) -> bool:
    end_time = time.time() + max(0.5, timeout_seconds)
    target = (target_mode or "").strip().lower()
    while time.time() < end_time:
        current = get_interface_mode(
            interface,
            fallback_iwconfig=fallback_iwconfig,
            infer_monitor_suffix=infer_monitor_suffix,
        )
        if current == target and is_interface_up(interface):
            return True
        time.sleep(max(0.05, poll_interval_seconds))
    return False


def wait_for_monitor_settle(settle_seconds: float) -> None:
    if settle_seconds <= 0:
        return
    time.sleep(settle_seconds)


def set_interface_type(
    interface: str,
    mode: str,
    *,
    enable_otherbss: bool = False,
    settle_seconds: float = 0.5,
) -> Tuple[bool, Optional[str]]:
    try:
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            check=False,
            stderr=subprocess.DEVNULL,
        )
        result = subprocess.run(
            ["iw", "dev", interface, "set", "type", mode],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "unknown error"

        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=False,
            stderr=subprocess.DEVNULL,
        )
        if mode == "monitor" and enable_otherbss:
            subprocess.run(
                ["iw", "dev", interface, "set", "monitor", "otherbss"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        if settle_seconds > 0:
            time.sleep(settle_seconds)
        return True, None
    except Exception as exc:
        return False, str(exc)


def set_interface_mode(
    interface: str,
    mode: str,
    *,
    timeout_seconds: float = 6.0,
    monitor_settle_seconds: float = 2.0,
    managed_settle_seconds: float = 0.8,
    enable_otherbss: bool = False,
    fallback_iwconfig: bool = True,
    infer_monitor_suffix: bool = False,
) -> Tuple[bool, Optional[str]]:
    ok, error = set_interface_type(
        interface,
        mode,
        enable_otherbss=enable_otherbss,
        settle_seconds=0.5,
    )
    if not ok:
        return False, error

    if not wait_for_interface_ready(
        interface,
        mode,
        timeout_seconds=timeout_seconds,
        fallback_iwconfig=fallback_iwconfig,
        infer_monitor_suffix=infer_monitor_suffix,
    ):
        return False, f"Interface {interface} did not become {mode} mode in time."

    mode_lower = (mode or "").strip().lower()
    if mode_lower == "monitor":
        wait_for_monitor_settle(monitor_settle_seconds)
    elif mode_lower == "managed" and managed_settle_seconds > 0:
        time.sleep(managed_settle_seconds)

    return True, None


def restore_managed_mode(interface: str) -> None:
    try:
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            check=False,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["iw", "dev", interface, "set", "type", "managed"],
            check=False,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=False,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

