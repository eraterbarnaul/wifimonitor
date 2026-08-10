"""Headless capture runner for unattended surveys (no GUI, no Qt).

Reuses the capture/database/report layers directly so it can run on a server or
drone. Heavy imports (scapy via capture) are deferred into ``run`` so argument
parsing stays importable without a wireless stack.

Example::

    sudo python -m wifimonitor.cli -i wlan0 --duration 300 --handshakes 5 \\
        --db survey.db --captures ./caps --report survey.html
"""

from __future__ import annotations

import argparse
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
    return parser


def run(args: argparse.Namespace) -> int:
    import logging
    import threading
    import time
    from pathlib import Path

    from .capture import MonitorService
    from .database import DatabaseManager
    from .interface import InterfaceManager
    from .logging_setup import configure_logging
    from .report import build_html_report

    configure_logging(Path.home() / ".wifimonitor")
    log = logging.getLogger("wifimonitor")

    db = DatabaseManager(Path(args.db))
    capture_dir = Path(args.captures)
    capture_dir.mkdir(parents=True, exist_ok=True)

    interface_manager = InterfaceManager()
    interface = args.interface
    if not args.no_monitor_setup:
        interface = interface_manager.ensure_monitor_mode(args.interface)

    stop = threading.Event()
    counters = {"handshakes": 0}

    def on_handshake(handshake) -> None:
        db.add_handshake(handshake)
        counters["handshakes"] += 1
        log.info("capture %s %s <-> %s (%s)", handshake.kind, handshake.bssid,
                 handshake.station_mac, handshake.quality)
        if args.handshakes and counters["handshakes"] >= args.handshakes:
            stop.set()

    service = MonitorService(
        interface=interface,
        capture_dir=capture_dir,
        on_access_point=db.upsert_access_point,
        on_station=db.upsert_station,
        on_handshake=on_handshake,
        on_log=log.info,
    )
    log.info("headless capture on %s", interface)
    service.start()
    deadline = time.time() + args.duration if args.duration > 0 else None
    try:
        while not stop.is_set():
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        service.stop()
        if not args.no_monitor_setup:
            try:
                interface_manager.disable_monitor_mode()
            except Exception as exc:  # noqa: BLE001
                log.warning("could not disable monitor mode: %s", exc)

    log.info("captured %d handshake(s)", counters["handshakes"])
    if args.report:
        access_points = [dict(row) for row in db.fetch_access_points()]
        stations = [dict(row) for row in db.fetch_stations()]
        handshakes = [dict(row) for row in db.fetch_handshakes()]
        Path(args.report).write_text(
            build_html_report(access_points, stations, handshakes), encoding="utf-8"
        )
        log.info("report written to %s", args.report)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
