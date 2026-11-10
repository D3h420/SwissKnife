"""Shared catalogue of workflows shown by both SwissKnife interfaces.

Add a workflow here to expose it in both the terminal and LCD menus.
The workflow itself stays in modules/ and may still need LCD input review.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Feature:
    label: str
    category: str
    script: str
    args: tuple[str, ...] = ()


FEATURES = (
    Feature("Recon", "Recon", "modules/recon.py"),
    Feature("Deauth", "Attacks", "modules/deauth.py"),
    Feature("Portal", "Attacks", "modules/portal.py"),
    Feature("Evil Twin", "Attacks", "modules/twins.py"),
    Feature("Handshaker", "Attacks", "modules/handshaker.py"),
    Feature("WiFi Poet", "Attacks", "modules/wifi_poet.py"),
    Feature("Dragon Drain", "Attacks", "modules/dragon_drain.py"),
    Feature("ARP scan", "Attacks", "modules/arp_scanner.py"),
    Feature("IP.CAM finder", "Attacks", "modules/ipcam_finder.py"),
    Feature("Start Wardrive", "Wardrive", "modules/wardrive.py", ("--start",)),
    Feature("GPS setup", "Wardrive", "modules/wardrive.py", ("--gps-setup",)),
)


def features_for(category: str) -> tuple[Feature, ...]:
    return tuple(feature for feature in FEATURES if feature.category == category)
