#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
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
    parser = argparse.ArgumentParser(description="SwissKnife WebUI recon sniffer action")
    parser.add_argument("--interface", default="auto", help="Wireless interface (default: auto external)")
    parser.add_argument(
        "--duration",
        type=int,
        default=90,
        help="Capture time in seconds (default: 90). Use 0 for unlimited.",
    )
    parser.add_argument(
        "--channels",
        default="",
        help="Comma-separated channel list (default: module defaults)",
    )
    parser.add_argument("--hop-interval", type=float, default=recon.DEFAULT_HOP_INTERVAL, help="Channel hop interval in seconds")
    parser.add_argument("--update-interval", type=float, default=1.0, help="Live table refresh in seconds")
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
    if args.duration < 0:
        raise SystemExit("--duration cannot be negative.")

    ensure_runtime_requirements()
    interface = resolve_tool_interface(args.interface, allow_builtin=args.allow_builtin)
    channels = parse_channels(args.channels)

    vendors = recon.load_vendor_db(recon.DEFAULT_VENDOR_DB)
    logging.info("[webui] Recon sniffer started on %s", interface)
    logging.info("[webui] Stop task from WebUI to end capture immediately.")
    if args.duration:
        logging.info("[webui] Auto-stop timeout: %ss", args.duration)
    if vendors:
        logging.info("Vendor lookup: enabled (%d entries).", len(vendors))
    else:
        logging.info("Vendor lookup: disabled.")

    stop_event = threading.Event()
    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def request_stop(signum: int, _frame) -> None:
        if stop_event.is_set():
            return
        signame = signal.Signals(signum).name
        logging.info("[webui] Received %s, stopping sniffer...", signame)
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    timer_thread = None
    if args.duration > 0:
        def stop_after_timeout() -> None:
            if stop_event.wait(args.duration):
                return
            logging.info("[webui] Sniffer timeout reached, stopping...")
            stop_event.set()

        timer_thread = threading.Thread(target=stop_after_timeout, daemon=True)
        timer_thread.start()

    original_mode = None
    mode_changed = False
    state = recon.SnifferState()
    try:
        original_mode, mode_changed = enable_monitor_mode(interface)
        recon.run_sniffer(
            interface=interface,
            stop_event=stop_event,
            state=state,
            channels=channels,
            hop_interval=args.hop_interval,
            update_interval=max(0.2, args.update_interval),
        )
        logging.info("")
        logging.info(recon.style(f"Total packets captured: {state.packet_count}", recon.STYLE_BOLD))
        for line in recon.format_sniffer_networks_lines(state.aps, vendors):
            logging.info("%s", line)
        logging.info("")
        for line in recon.format_probe_lines(state.probe_counts, state.probe_total):
            logging.info("%s", line)
        logging.info("")
        logging.info("[webui] Recon sniffer finished.")
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)
        if timer_thread:
            timer_thread.join(timeout=0.2)
        restore_interface_mode(
            interface=interface,
            original_mode=original_mode,
            changed=mode_changed,
            keep_monitor=args.keep_monitor,
        )


if __name__ == "__main__":
    main()
