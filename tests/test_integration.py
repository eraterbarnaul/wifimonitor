"""Integration tests for the use-case layer."""
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def uc(tmp_path):
    """Create a MonitorUseCase with mocked interface and capture dependencies."""
    with patch("wifimonitor.usecases.InterfaceManager") as MockIM, \
         patch("wifimonitor.usecases.GpsReader"):
        mock_im = MockIM.return_value
        mock_im.list_wireless_interfaces.return_value = ["wlan0"]
        mock_im.ensure_monitor_mode.return_value = "wlan0mon"
        mock_im.get_injection_interface.return_value = "wlan0mon"
        mock_im.base_interface = None
        mock_im.monitor_interface = "wlan0mon"

        from wifimonitor.events import EventBus
        from wifimonitor.usecases import MonitorUseCase

        db_path = tmp_path / "test.db"
        capture_dir = tmp_path / "captures"
        capture_dir.mkdir()
        bus = EventBus()
        use_case = MonitorUseCase(db_path=db_path, capture_dir=capture_dir, bus=bus)
        use_case.interface_manager = mock_im
        yield use_case


def test_set_interface_emits_event(uc):
    events = []
    uc.bus.subscribe("interface_ready", lambda iface: events.append(iface))
    uc.set_interface("wlan0")
    assert uc.base_interface == "wlan0"
    assert "wlan0" in events


def test_refresh_interfaces(uc):
    events = []
    uc.bus.subscribe("interface_list_changed", lambda lst: events.append(lst))
    result = uc.refresh_interfaces()
    assert result == ["wlan0"]
    assert ["wlan0"] in events


def test_handle_access_point(uc):
    from wifimonitor.models import AccessPoint
    events = []
    uc.bus.subscribe("access_point_discovered", lambda d: events.append(d))
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", essid="TestNet", channel=6, encryption="WPA2")
    uc._handle_access_point(ap)
    assert "aa:bb:cc:dd:ee:ff" in uc.access_points
    assert len(events) == 1
    assert events[0]["essid"] == "TestNet"


def test_handle_station_tracks_clients(uc):
    from wifimonitor.models import Station
    sta = Station(mac="11:22:33:44:55:66", associated_bssid="aa:bb:cc:dd:ee:ff")
    uc._handle_station(sta)
    clients = uc.get_clients_for_ap("aa:bb:cc:dd:ee:ff")
    assert "11:22:33:44:55:66" in clients


def test_handle_handshake_stored(uc):
    from wifimonitor.models import Handshake
    events = []
    uc.bus.subscribe("handshake_captured", lambda d: events.append(d))
    hs = Handshake(bssid="aa:bb:cc:dd:ee:ff", station_mac="11:22:33:44:55:66",
                   capture_path="/tmp/test.pcap", quality="crackable")
    uc._handle_handshake(hs)
    assert len(events) == 1
    rows = uc.db.fetch_handshakes()
    assert len(rows) == 1


def test_export_csv(uc, tmp_path):
    from wifimonitor.models import AccessPoint, Station
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", essid="Net1", channel=1)
    uc._handle_access_point(ap)
    sta = Station(mac="11:22:33:44:55:66", associated_bssid="aa:bb:cc:dd:ee:ff")
    uc._handle_station(sta)
    # Force write to bypass rate limiting
    time.sleep(0.1)
    uc.db._last_ap_write.clear()
    uc.db._last_sta_write.clear()
    uc._handle_access_point(ap)
    uc._handle_station(sta)

    out = tmp_path / "export.csv"
    clients_path = uc.export_csv(out)
    assert out.exists()
    assert clients_path.exists()


def test_load_access_points_from_db(uc):
    from wifimonitor.models import AccessPoint
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", essid="Loaded", channel=11)
    uc.db.upsert_access_point_force(ap)
    rows = uc.load_access_points()
    assert len(rows) >= 1
    assert "aa:bb:cc:dd:ee:ff" in uc.access_points


def test_security_alert_suppressed_during_deauth(uc):
    alerts = []
    uc.bus.subscribe("security_alert", lambda msg: alerts.append(msg))
    # Simulate deauth running
    mock_deauth = MagicMock()
    mock_deauth.is_running.return_value = True
    uc.deauth_service = mock_deauth
    uc._handle_alert("test alert")
    assert len(alerts) == 0  # Suppressed


def test_security_alert_emitted_normally(uc):
    alerts = []
    uc.bus.subscribe("security_alert", lambda msg: alerts.append(msg))
    uc._handle_alert("real alert")
    assert "real alert" in alerts


def test_probe_tracking(uc):
    probes = []
    uc.bus.subscribe("probe_discovered", lambda d: probes.append(d))
    uc._handle_probe("aa:bb:cc:dd:ee:ff", "ProbeSSID")
    assert "ProbeSSID" in uc.probes_by_client["aa:bb:cc:dd:ee:ff"]
    assert len(probes) == 1
