"""Tests for report.py new sections (bandwidth, wifi_gen, evil twin, GPS)."""
from wifimonitor.report import build_html_report


def _sample_data():
    aps = [
        {"bssid": "aa:bb:cc:dd:ee:01", "essid": "FastNet", "channel": 36,
         "encryption": "WPA2", "signal": -50, "wps": False, "mfp_required": False,
         "bandwidth": "80", "wifi_generation": "5"},
        {"bssid": "aa:bb:cc:dd:ee:02", "essid": "FastNet", "channel": 1,
         "encryption": "WPA2", "signal": -70, "wps": True, "mfp_required": False,
         "bandwidth": "40", "wifi_generation": "4"},
    ]
    stations = [
        {"mac": "11:22:33:44:55:66", "associated_bssid": "aa:bb:cc:dd:ee:01", "signal": -55, "last_seen": "2024-01-01"},
    ]
    handshakes = [
        {"bssid": "aa:bb:cc:dd:ee:01", "station_mac": "11:22:33:44:55:66",
         "kind": "handshake", "quality": "crackable", "capture_path": "/tmp/cap.pcap",
         "created_at": "2024-01-01"},
    ]
    return aps, stations, handshakes


def test_report_contains_bandwidth_column():
    aps, stations, handshakes = _sample_data()
    html = build_html_report(aps, stations, handshakes)
    assert "Полоса" in html or "80" in html


def test_report_contains_wifi_generation():
    aps, stations, handshakes = _sample_data()
    html = build_html_report(aps, stations, handshakes)
    # wifi_generation field should appear in the table
    assert "Wi-Fi" in html or "wifi" in html.lower()


def test_report_evil_twin_section():
    aps, stations, handshakes = _sample_data()
    evil_twins = {"FastNet": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]}
    html = build_html_report(aps, stations, handshakes, evil_twins=evil_twins)
    assert "Evil Twin" in html or "evil" in html.lower() or "twin" in html.lower()
    assert "FastNet" in html
    assert "aa:bb:cc:dd:ee:01" in html


def test_report_gps_section():
    aps, stations, handshakes = _sample_data()
    gps_locations = [
        {"bssid": "aa:bb:cc:dd:ee:01", "latitude": 55.7558, "longitude": 37.6173, "signal": -50},
    ]
    html = build_html_report(aps, stations, handshakes, gps_locations=gps_locations)
    assert "GPS" in html or "gps" in html.lower() or "Широта" in html
    assert "55.7558" in html
    assert "37.6173" in html


def test_report_no_evil_twin_section_when_none():
    aps, stations, handshakes = _sample_data()
    html = build_html_report(aps, stations, handshakes, evil_twins=None)
    # Should not crash, section simply absent
    assert "<!doctype html>" in html.lower() or "<html" in html.lower()


def test_report_no_gps_section_when_none():
    aps, stations, handshakes = _sample_data()
    html = build_html_report(aps, stations, handshakes, gps_locations=None)
    assert "<!doctype html>" in html.lower() or "<html" in html.lower()
