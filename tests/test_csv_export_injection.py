"""Tests for CSV injection protection."""
from wifimonitor.csv_export import _sanitize_cell, CsvExporter


def test_sanitize_normal():
    assert _sanitize_cell("hello") == "hello"
    assert _sanitize_cell("192.168.1.1") == "192.168.1.1"
    assert _sanitize_cell(None) == ""


def test_sanitize_equals():
    assert _sanitize_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"


def test_sanitize_plus():
    assert _sanitize_cell("+cmd|'/C calc'!A0") == "'+cmd|'/C calc'!A0"


def test_sanitize_minus():
    assert _sanitize_cell("-10+20") == "'-10+20"


def test_sanitize_at():
    assert _sanitize_cell("@SUM(A1:A2)") == "'@SUM(A1:A2)"


def test_sanitize_tab():
    assert _sanitize_cell("\tcmd") == "'\tcmd"


def test_export_with_malicious_essid(tmp_path):
    exporter = CsvExporter()
    aps = [{"bssid": "aa:bb:cc:dd:ee:ff", "essid": "=EVIL()", "channel": 1,
            "encryption": "WPA2", "signal": -50, "bandwidth": "", "wifi_generation": "",
            "last_seen": "2024-01-01"}]
    out = tmp_path / "test.csv"
    exporter.export(out, aps, [])
    content = out.read_text()
    assert "'=EVIL()" in content
    assert "=EVIL()" not in content.replace("'=EVIL()", "")
