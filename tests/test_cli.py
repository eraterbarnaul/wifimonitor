"""Tests for the headless CLI argument parsing (no scapy needed)."""

from wifimonitor.cli import build_parser


def test_defaults():
    args = build_parser().parse_args(["-i", "wlan0"])
    assert args.interface == "wlan0"
    assert args.db == "wifimonitor.db"
    assert args.captures == "captures"
    assert args.duration == 0.0
    assert args.handshakes == 0
    assert args.report == ""
    assert args.no_monitor_setup is False


def test_full_args():
    args = build_parser().parse_args([
        "-i", "wlan1", "--db", "s.db", "--captures", "/caps",
        "--duration", "120", "--handshakes", "3", "--report", "r.html",
        "--no-monitor-setup",
    ])
    assert args.interface == "wlan1"
    assert args.duration == 120.0
    assert args.handshakes == 3
    assert args.report == "r.html"
    assert args.no_monitor_setup is True


def test_api_flags_default_to_localhost():
    args = build_parser().parse_args(["-i", "wlan0"])
    assert args.api is False
    assert args.api_host == "127.0.0.1"
    assert args.api_port == 8080


def test_api_flags_parse():
    args = build_parser().parse_args(["-i", "wlan0", "--api", "--api-host", "0.0.0.0", "--api-port", "9000"])
    assert args.api is True
    assert args.api_host == "0.0.0.0"
    assert args.api_port == 9000


def test_interface_required():
    try:
        build_parser().parse_args([])
    except SystemExit:
        return
    raise AssertionError("expected SystemExit when --interface is missing")
