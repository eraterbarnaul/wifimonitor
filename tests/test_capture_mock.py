"""Unit tests for capture module with mocked scapy."""
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from collections import defaultdict

import pytest


@pytest.fixture
def monitor_service(tmp_path):
    """Create a MonitorService with mocked scapy sniff."""
    with patch("wifimonitor.capture.sniff") as mock_sniff, \
         patch("wifimonitor.capture.wrpcap") as mock_wrpcap:
        from wifimonitor.capture import MonitorService
        svc = MonitorService(
            interface="wlan0mon",
            capture_dir=tmp_path,
            enable_channel_hopper=False,
        )
        yield svc, mock_sniff, mock_wrpcap


def test_start_and_stop(monitor_service):
    svc, mock_sniff, _ = monitor_service
    mock_sniff.side_effect = lambda **kwargs: time.sleep(0.1)
    svc.start()
    assert svc.is_running()
    time.sleep(0.2)
    svc.stop()
    time.sleep(0.3)
    # After stop, should not be running
    assert not svc._running.is_set()


def test_lock_channel(monitor_service):
    svc, _, _ = monitor_service
    with patch("wifimonitor.capture.set_interface_channel", return_value=True) as mock_set:
        result = svc.lock_channel(6)
        assert result is True
        assert svc._locked_channel == 6
        mock_set.assert_called_with("wlan0mon", 6)


def test_unlock_channel(monitor_service):
    svc, _, _ = monitor_service
    svc._locked_channel = 6
    svc._running.set()
    svc.unlock_channel()
    assert svc._locked_channel is None


def test_callbacks_registered(tmp_path):
    with patch("wifimonitor.capture.sniff"), patch("wifimonitor.capture.wrpcap"):
        from wifimonitor.capture import MonitorService
        on_ap = MagicMock()
        on_sta = MagicMock()
        on_hs = MagicMock()
        svc = MonitorService(
            interface="wlan0mon",
            capture_dir=tmp_path,
            on_access_point=on_ap,
            on_station=on_sta,
            on_handshake=on_hs,
            enable_channel_hopper=False,
        )
        assert svc.on_access_point is on_ap
        assert svc.on_station is on_sta
        assert svc.on_handshake is on_hs


def test_channel_hopper_disabled(monitor_service):
    svc, _, _ = monitor_service
    assert svc._channel_hopper is None


def test_pcap_writer_created(monitor_service):
    svc, _, _ = monitor_service
    assert svc._pcap_writer is not None


def test_evil_twin_detector_created(monitor_service):
    svc, _, _ = monitor_service
    from wifimonitor.detect import EvilTwinDetector
    assert isinstance(svc._evil_twin_detector, EvilTwinDetector)
