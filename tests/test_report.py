"""Unit tests for the HTML report generator."""

from wifimonitor.report import build_html_report

APS = [
    {"bssid": "B8:27:EB:01:02:03", "essid": "HomeNet", "channel": 6, "encryption": "WPA2",
     "signal": -45, "wps": 1, "mfp_required": 0},
    {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Guest", "channel": 36, "encryption": "WPA3",
     "signal": -70, "wps": 0, "mfp_required": 1},
]
STATIONS = [
    {"mac": "11:22:33:44:55:66", "associated_bssid": "B8:27:EB:01:02:03", "signal": -50, "last_seen": "t"},
]
HANDSHAKES = [
    {"bssid": "B8:27:EB:01:02:03", "station_mac": "11:22:33:44:55:66", "kind": "pmkid",
     "capture_path": "/x/pmkid.pcap", "created_at": "t"},
]


def test_report_is_valid_html_with_sections():
    html = build_html_report(APS, STATIONS, HANDSHAKES)
    assert html.startswith("<!doctype html>")
    assert html.rstrip().endswith("</html>")
    for heading in ("Точки доступа", "Клиенты", "Захваты"):
        assert heading in html
    # PMKID capture makes the WPS WPA2 network a high-priority verdict
    assert "Высокий" in html
    # OUI vendor is resolved for the Raspberry Pi prefix
    assert "Raspberry Pi" in html


def test_report_escapes_essid():
    aps = [{"bssid": "AA:BB", "essid": "<script>alert(1)</script>", "channel": 1,
            "encryption": "WPA2", "signal": -40, "wps": 0, "mfp_required": 0}]
    html = build_html_report(aps, [], [])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
