"""Tests for WiGLE CSV export."""

from wifimonitor.wardriving import build_wigle_csv

LOCATIONS = [
    {"bssid": "AA:BB:CC:DD:EE:FF", "latitude": 55.75, "longitude": 37.61,
     "altitude": 150.0, "signal": -42, "timestamp": "2026-08-10 07:00:00"},
    {"bssid": "11:22:33:44:55:66", "latitude": 55.76, "longitude": 37.62,
     "altitude": None, "signal": -70, "timestamp": "2026-08-10 07:01:00"},
]
AP_INDEX = {
    "AA:BB:CC:DD:EE:FF": {"essid": "HomeNet", "channel": 6, "encryption": "WPA2"},
}


def test_wigle_header_and_columns():
    text = build_wigle_csv(LOCATIONS, AP_INDEX)
    lines = text.splitlines()
    assert lines[0].startswith("WigleWifi-1.4")
    assert lines[1].split(",")[0] == "MAC"
    assert "CurrentLatitude" in lines[1] and "Type" in lines[1]


def test_wigle_rows():
    lines = build_wigle_csv(LOCATIONS, AP_INDEX).splitlines()
    # first data row: known AP -> SSID/channel/encryption filled
    row1 = lines[2].split(",")
    assert row1[0] == "AA:BB:CC:DD:EE:FF"
    assert row1[1] == "HomeNet"
    assert row1[2] == "WPA2"
    assert row1[4] == "6"
    assert row1[6] == "55.75" and row1[7] == "37.61"
    assert row1[10] == "WIFI"
    # second row: unknown AP -> empty SSID, empty altitude
    row2 = lines[3].split(",")
    assert row2[0] == "11:22:33:44:55:66"
    assert row2[1] == ""
    assert row2[8] == ""  # altitude None -> empty


def test_wigle_empty():
    text = build_wigle_csv([], {})
    assert text.splitlines()[0].startswith("WigleWifi-1.4")
