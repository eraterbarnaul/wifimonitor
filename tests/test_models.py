"""Tests for the plain-data dataclasses shared across the app layers."""

from datetime import datetime, timezone

from wifimonitor.models import AccessPoint, GpsCoordinate, Handshake, Station


def test_access_point_defaults():
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF")
    assert ap.essid is None
    assert ap.wps is False
    assert ap.mfp_required is False
    assert ap.bandwidth == ""
    assert isinstance(ap.last_seen, datetime)
    assert ap.last_seen.tzinfo is not None


def test_access_point_last_seen_defaults_are_independent():
    a = AccessPoint(bssid="AA:BB:CC:DD:EE:FF")
    b = AccessPoint(bssid="11:22:33:44:55:66")
    assert a.last_seen is not b.last_seen  # not sharing one mutable default


def test_station_defaults():
    sta = Station(mac="AA:BB:CC:DD:EE:FF")
    assert sta.associated_bssid is None
    assert sta.signal is None


def test_handshake_defaults():
    hs = Handshake(bssid="AA:BB:CC:DD:EE:FF", station_mac="11:22:33:44:55:66", capture_path="/tmp/x.pcap")
    assert hs.kind == "handshake"
    assert hs.quality == ""


def test_gps_coordinate_requires_lat_lon():
    gps = GpsCoordinate(latitude=55.75, longitude=37.61)
    assert gps.altitude is None
    assert gps.accuracy is None
    assert isinstance(gps.timestamp, datetime)
    assert gps.timestamp.tzinfo == timezone.utc
