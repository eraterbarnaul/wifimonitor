"""Unit tests for WifiMonitorController with mocks."""
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


@pytest.fixture
def controller(tmp_path):
    """Create controller with mocked dependencies."""
    with patch("wifimonitor.controller.EventBus") as MockBus, \
         patch("wifimonitor.controller.MonitorUseCase") as MockUC:
        mock_bus = MockBus.return_value
        mock_uc = MockUC.return_value
        mock_uc.bus = mock_bus
        
        # Need to import after patches
        from wifimonitor.controller import WifiMonitorController
        ctrl = WifiMonitorController(db_path=tmp_path / "test.db", capture_dir=tmp_path / "caps")
        ctrl._uc = mock_uc
        ctrl._uc.access_points = {}
        ctrl._uc.clients_by_ap = {}
        ctrl._uc.probes_by_client = {}
        ctrl._uc.monitor_service = None
        ctrl._uc.deauth_service = None
        ctrl._uc.current_interface = None
        ctrl._uc.base_interface = None
        yield ctrl, mock_uc


def test_set_interface_delegates(controller):
    ctrl, mock_uc = controller
    ctrl.set_interface("wlan0")
    mock_uc.set_interface.assert_called_once_with("wlan0")


def test_start_capture_delegates(controller):
    ctrl, mock_uc = controller
    ctrl.start_capture()
    mock_uc.start_capture.assert_called_once()


def test_stop_capture_delegates(controller):
    ctrl, mock_uc = controller
    ctrl.stop_capture()
    mock_uc.stop_capture.assert_called_once()


def test_refresh_interfaces_delegates(controller):
    ctrl, mock_uc = controller
    mock_uc.refresh_interfaces.return_value = ["wlan0", "wlan1"]
    result = ctrl.refresh_interfaces()
    assert result == ["wlan0", "wlan1"]


def test_get_clients_for_ap_delegates(controller):
    ctrl, mock_uc = controller
    mock_uc.get_clients_for_ap.return_value = ["aa:bb:cc:dd:ee:ff"]
    result = ctrl.get_clients_for_ap("11:22:33:44:55:66")
    assert result == ["aa:bb:cc:dd:ee:ff"]


def test_start_deauth_delegates(controller):
    ctrl, mock_uc = controller
    ctrl.start_deauth("aa:bb:cc:dd:ee:ff", ["11:22:33:44:55:66"], 5, 1.0)
    mock_uc.start_deauth.assert_called_once_with("aa:bb:cc:dd:ee:ff", ["11:22:33:44:55:66"], 5, 1.0)


def test_stop_deauth_delegates(controller):
    ctrl, mock_uc = controller
    ctrl.stop_deauth()
    mock_uc.stop_deauth.assert_called_once()


def test_export_hashcat_delegates(controller):
    ctrl, mock_uc = controller
    ctrl.export_hashcat(Path("/tmp/cap.pcap"), Path("/tmp/out.hc22000"))
    mock_uc.export_hashcat.assert_called_once()


def test_start_auto_attack_delegates(controller):
    ctrl, mock_uc = controller
    ctrl.start_auto_attack("aa:bb:cc:dd:ee:ff", ["11:22:33:44:55:66"], channel=6)
    mock_uc.start_auto_attack.assert_called_once()


def test_load_access_points_delegates(controller):
    ctrl, mock_uc = controller
    mock_uc.load_access_points.return_value = [{"bssid": "aa:bb"}]
    result = ctrl.load_access_points()
    assert result == [{"bssid": "aa:bb"}]
