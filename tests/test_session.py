"""Tests for multi-session comparison."""
import time
from pathlib import Path

from wifimonitor.database import DatabaseManager
from wifimonitor.models import AccessPoint


def test_create_and_compare_sessions(tmp_path):
    db = DatabaseManager(tmp_path / "sessions.db")

    # Session 1: AP1 and AP2
    s1 = db.create_session("wlan0", "first scan")
    aps1 = [
        {"bssid": "aa:bb:cc:dd:ee:01", "essid": "Net1", "channel": 1, "encryption": "WPA2", "signal": -50},
        {"bssid": "aa:bb:cc:dd:ee:02", "essid": "Net2", "channel": 6, "encryption": "WPA2", "signal": -60},
    ]
    db.snapshot_session(s1, aps1, [])
    db.end_session(s1)

    # Session 2: AP2 (changed encryption) and AP3 (new)
    s2 = db.create_session("wlan0", "second scan")
    aps2 = [
        {"bssid": "aa:bb:cc:dd:ee:02", "essid": "Net2", "channel": 6, "encryption": "WPA3", "signal": -55},
        {"bssid": "aa:bb:cc:dd:ee:03", "essid": "Net3", "channel": 11, "encryption": "OPEN", "signal": -70},
    ]
    db.snapshot_session(s2, aps2, [])
    db.end_session(s2)

    # Compare
    diff = db.compare_sessions(s1, s2)
    assert len(diff["new"]) == 1
    assert diff["new"][0]["bssid"] == "aa:bb:cc:dd:ee:03"
    assert len(diff["gone"]) == 1
    assert diff["gone"][0]["bssid"] == "aa:bb:cc:dd:ee:01"
    assert len(diff["changed"]) == 1
    assert diff["changed"][0]["bssid"] == "aa:bb:cc:dd:ee:02"
    assert diff["changed"][0]["changes"]["encryption"]["before"] == "WPA2"
    assert diff["changed"][0]["changes"]["encryption"]["after"] == "WPA3"


def test_fetch_sessions(tmp_path):
    db = DatabaseManager(tmp_path / "s.db")
    s1 = db.create_session("wlan0")
    db.end_session(s1)
    sessions = db.fetch_sessions()
    assert len(sessions) == 1
