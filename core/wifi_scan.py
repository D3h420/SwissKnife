"""Select the shared scan command for CLI and packaged graphical interfaces."""

from __future__ import annotations

import os


def scan_command(interface: str) -> list[str]:
    helper = os.environ.get("SWISSKNIFE_WIFI_SCAN_HELPER")
    if helper:
        return ["sudo", "-n", helper, interface]
    return ["iw", "dev", interface, "scan"]
