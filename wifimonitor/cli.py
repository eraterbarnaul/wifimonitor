"""Headless capture runner for unattended surveys (no GUI, no Qt).

Reuses the shared use-case layer so it gets the same logic as the GUI.

Example::

    sudo python -m wifimonitor.cli -i wlan0 --duration 300 --handshakes 5 \\
        --db survey.db --captures ./caps --report survey.html
"""

from __future__ import annotations

import argparse
import threading
import time
from typing import List, Optional


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifimonitor-cli",
        description="Headless Wi-Fi capture (unattended survey).",
    )
    parser.add_argument("-i", "--interface", required=True, help="wireless interface")
    parser.add_argument("--db", default="wifimonitor.db", help="SQLite database path")
    parser.add_argument("--captures", default="captures", help="directory for pcap captures")
    parser.add_argument(
        "--duration", type=float, default=0.0,
        help="stop after N seconds (0 = run until --handshakes or Ctrl-C)",
    )
    parser.add_argument(
        "--handshakes", type=int, default=0,
        help="stop after N captures (0 = no limit)",
    )
    parser.add_argument("--report", default="", help="write an HTML report here on exit")
    parser.add_argument(
        "--no-monitor-setup", action="store_true",
        help="interface is already in monitor mode (skip airmon-ng)",
    )
    parser.add_argument(
        "--secondary", default="",
        help="secondary interface for injection (dual-adapter mode)",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    import logging
    from pathlib import Path

    from .events import EventBus, Events
    from .logging_setup import configure_logging
    from .usecases import MonitorUseCase

    configure_logging(Path.home() / ".wifimonitor")
    log = logging.getLogger("wifimonitor")

    capture_dir = Path(args.captures)
    capture_dir.mkdir(parents=True, exist_ok=True)

    bus = EventBus()
    uc = MonitorUseCase(db_path=Path(args.db), capture_dir=capture_dir, bus=bus)

    stop = threading.Event()
    counters = {"handshakes": 0}

    def on_handshake(data: dict) -> None:
        counters["handshakes"] += 1
        log.info("capture %s %s <-> %s (%s)", data.get("kind"), data.get("bssid"),
                 data.get("station_mac"), data.get("quality"))
        if args.handshakes and counters["handshakes"] >= args.handshakes:
            stop.set()

    bus.subscribe(Events.HANDSHAKE_CAPTURED, on_handshake)

    # Setup interface
    uc.set_interface(args.interface)
    if args.secondary:
        uc.set_secondary_interface(args.secondary)

    if args.no_monitor_setup:
        uc.interface_manager.monitor_interface = args.interface
        uc.interface_manager._auto_started = False
    
    log.info("headless capture on %s", args.interface)
    uc.start_capture()

    deadline = time.time() + args.duration if args.duration > 0 else None
    try:
        while not stop.is_set():
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        uc.stop_capture()

    log.info("captured %d handshake(s)", counters["handshakes"])
    if args.report:
        uc.export_report(Path(args.report))
        log.info("report written to %s", args.report)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
