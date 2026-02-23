#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules import bluetooth  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SwissKnife WebUI bluetooth scan action")
    parser.add_argument("--interface", default="auto", help="Bluetooth interface/controller (default: auto)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Auto-stop timeout in seconds (default: 30). Use 0 for unlimited.",
    )
    return parser.parse_args()


def ensure_runtime_requirements() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Bluetooth WebUI action must run as root.")
    if not bluetooth.tool_exists("bluetoothctl"):
        raise RuntimeError("Missing required tool: bluetoothctl")


def resolve_interface(requested: str) -> str:
    interfaces = bluetooth.list_hci_interfaces()
    if requested and requested != "auto":
        if interfaces and requested not in interfaces:
            raise RuntimeError(f"Bluetooth interface '{requested}' is not available.")
        return requested
    if not interfaces:
        return "hci0"
    return bluetooth.select_hci_interface(interfaces)


def serialize_devices(devices: list[bluetooth.BluetoothDevice]) -> list[dict]:
    payload: list[dict] = []
    for device in devices:
        payload.append(
            {
                "mac": device.mac,
                "name": device.name,
                "rssi": device.rssi,
            }
        )
    return payload


def main() -> None:
    args = parse_args()
    if args.timeout < 0:
        raise SystemExit("--timeout cannot be negative.")

    ensure_runtime_requirements()
    interface = resolve_interface((args.interface or "").strip())

    logging.info("[webui] Bluetooth scan started on %s", interface)
    if args.timeout > 0:
        logging.info("[webui] Auto-stop timeout: %ss", args.timeout)
    else:
        logging.info("[webui] Auto-stop timeout disabled. Use WebUI Stop to finish.")

    timer_stop = threading.Event()
    timer_thread = None
    if args.timeout > 0:
        def stop_after_timeout() -> None:
            if timer_stop.wait(args.timeout):
                return
            try:
                os.kill(os.getpid(), signal.SIGINT)
            except OSError:
                pass

        timer_thread = threading.Thread(target=stop_after_timeout, daemon=True)
        timer_thread.start()

    try:
        started = time.time()
        devices = bluetooth.scan_bt_devices_live(interface)
        payload = {
            "kind": "bluetooth_scan",
            "running": False,
            "timestamp": int(time.time()),
            "interface": interface,
            "timeout": int(args.timeout),
            "duration": max(0, int(time.time() - started)),
            "device_count": len(devices),
            "devices": serialize_devices(devices),
        }
        print(f"[webui-result] {json.dumps(payload, ensure_ascii=False)}", flush=True)
        logging.info("[webui] Bluetooth scan finished.")
    finally:
        timer_stop.set()
        if timer_thread:
            timer_thread.join(timeout=0.2)


if __name__ == "__main__":
    main()
