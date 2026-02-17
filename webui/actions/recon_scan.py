#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules import recon  # noqa: E402
from webui.actions.recon_common import (  # noqa: E402
    enable_monitor_mode,
    ensure_runtime_requirements,
    parse_channels,
    resolve_tool_interface,
    restore_interface_mode,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SwissKnife WebUI recon scanner action")
    parser.add_argument("--interface", default="auto", help="Wireless interface (default: auto external)")
    parser.add_argument("--duration", type=int, default=24, help="Scan duration in seconds (default: 24)")
    parser.add_argument(
        "--channels",
        default="",
        help="Comma-separated channel list (default: module defaults)",
    )
    parser.add_argument("--hop-interval", type=float, default=recon.DEFAULT_HOP_INTERVAL, help="Channel hop interval in seconds")
    parser.add_argument("--update-interval", type=float, default=recon.DEFAULT_LIVE_UPDATE_INTERVAL, help="Live table refresh in seconds")
    parser.add_argument(
        "--keep-monitor",
        action="store_true",
        help="Keep interface in monitor mode after task exits.",
    )
    parser.add_argument(
        "--allow-builtin",
        action="store_true",
        help="Allow using the built-in AP interface (not recommended).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.duration <= 0:
        raise SystemExit("--duration must be greater than zero.")

    ensure_runtime_requirements()
    interface = resolve_tool_interface(args.interface, allow_builtin=args.allow_builtin)
    channels = parse_channels(args.channels)

    vendors = recon.load_vendor_db(recon.DEFAULT_VENDOR_DB)
    logging.info("[webui] Recon scan started on %s", interface)
    if vendors:
        logging.info("Vendor lookup: enabled (%d entries).", len(vendors))
    else:
        logging.info("Vendor lookup: disabled.")

    original_mode = None
    mode_changed = False
    try:
        original_mode, mode_changed = enable_monitor_mode(interface)

        update_cb = lambda snapshot, remaining: recon.display_scan_live_update(
            snapshot,
            vendors,
            remaining,
            interface,
        )
        aps = recon.scan_wireless_networks_aircrack(
            interface=interface,
            duration_seconds=args.duration,
            channels=channels,
            hop_interval=args.hop_interval,
            update_interval=args.update_interval,
            on_update=update_cb,
        )
        recon.display_scan_results(aps, vendors)
        logging.info("[webui] Recon scan finished.")
    except KeyboardInterrupt:
        logging.warning("[webui] Recon scan interrupted by operator.")
    finally:
        restore_interface_mode(
            interface=interface,
            original_mode=original_mode,
            changed=mode_changed,
            keep_monitor=args.keep_monitor,
        )


if __name__ == "__main__":
    main()
