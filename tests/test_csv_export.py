"""Unit tests for the CSV exporter."""

import csv
import tempfile
from pathlib import Path

from wifimonitor.csv_export import CsvExporter

APS = [
    {"bssid": "AA:BB", "essid": "Net1", "channel": 6, "encryption": "WPA2", "signal": -40, "bandwidth": "", "wifi_generation": "", "last_seen": "t1"},
    {"bssid": "CC:DD", "essid": None, "channel": 36, "encryption": "WPA2/WPA3", "signal": -70, "bandwidth": "", "wifi_generation": "", "last_seen": "t2"},
]
STATIONS = [
    {"mac": "11:22", "associated_bssid": "AA:BB", "signal": -50, "last_seen": "t3"},
]


def test_csv_export_writes_both_files():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "networks.csv"
        clients = CsvExporter().export(out, APS, STATIONS)

        assert out.exists()
        assert clients == out.with_name("networks_clients.csv")
        assert clients.exists()

        ap_rows = list(csv.reader(out.open(encoding="utf-8")))
        assert ap_rows[0] == ["BSSID", "ESSID", "Channel", "Encryption", "Signal", "Bandwidth", "WiFi Gen", "Last Seen"]
        assert ap_rows[1][0] == "AA:BB" and ap_rows[1][2] == "6"
        assert ap_rows[2][1] == ""  # None essid becomes empty

        client_rows = list(csv.reader(clients.open(encoding="utf-8")))
        assert client_rows[0] == ["MAC", "Associated BSSID", "Signal", "Last Seen"]
        assert client_rows[1][0] == "11:22"
