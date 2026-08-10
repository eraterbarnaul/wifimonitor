"""Tests for GPS database integration."""
from wifimonitor.database import DatabaseManager


def test_record_ap_location(tmp_path):
    db = DatabaseManager(tmp_path / "gps.db")
    db.record_ap_location("aa:bb:cc:dd:ee:ff", 55.7558, 37.6173, altitude=150.0, signal=-45)
    rows = db.fetch_ap_locations("aa:bb:cc:dd:ee:ff")
    assert len(rows) == 1
    assert rows[0]["latitude"] == 55.7558
    assert rows[0]["longitude"] == 37.6173
    assert rows[0]["altitude"] == 150.0
    assert rows[0]["signal"] == -45


def test_record_ap_location_updates_signal(tmp_path):
    db = DatabaseManager(tmp_path / "gps.db")
    # First record with weak signal
    db.record_ap_location("aa:bb:cc:dd:ee:ff", 55.7558, 37.6173, signal=-80)
    # Same location, stronger signal
    db.record_ap_location("aa:bb:cc:dd:ee:ff", 55.7558, 37.6173, signal=-40)
    rows = db.fetch_ap_locations("aa:bb:cc:dd:ee:ff")
    assert len(rows) == 1
    assert rows[0]["signal"] == -40  # Best signal wins


def test_record_multiple_locations(tmp_path):
    db = DatabaseManager(tmp_path / "gps.db")
    db.record_ap_location("aa:bb:cc:dd:ee:ff", 55.7558, 37.6173, signal=-50)
    db.record_ap_location("aa:bb:cc:dd:ee:ff", 55.7560, 37.6175, signal=-60)
    rows = db.fetch_ap_locations("aa:bb:cc:dd:ee:ff")
    assert len(rows) == 2


def test_fetch_all_locations(tmp_path):
    db = DatabaseManager(tmp_path / "gps.db")
    db.record_ap_location("aa:bb:cc:dd:ee:01", 55.0, 37.0, signal=-50)
    db.record_ap_location("aa:bb:cc:dd:ee:02", 56.0, 38.0, signal=-60)
    rows = db.fetch_ap_locations()
    assert len(rows) == 2


def test_fetch_empty(tmp_path):
    db = DatabaseManager(tmp_path / "gps.db")
    rows = db.fetch_ap_locations("nonexistent")
    assert len(rows) == 0
