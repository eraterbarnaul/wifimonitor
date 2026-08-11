"""Unit tests for capture module with mocked scapy."""
import time
from unittest.mock import MagicMock, patch

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


# --- _frame_bssid: addr3 is only reliably the BSSID for management frames;
# ordinary ToDS/FromDS data traffic needs the right address slot instead. ---
#
# NB: Dot11()'s default FCfield is a shared object across instances that
# don't override it — mutating `pkt.FCfield.to_DS = 1` in place leaks into
# every other Dot11() built afterwards without an explicit FCfield. Pass the
# flag bits at construction time instead (bit 0 = to_DS, bit 1 = from_DS) so
# each packet's addressing mode is actually isolated.
_TO_DS = 1
_FROM_DS = 2

BSSID = "aa:aa:aa:aa:aa:aa"
STATION = "bb:bb:bb:bb:bb:bb"
FAR_SIDE = "cc:cc:cc:cc:cc:cc"  # e.g. a router/host beyond the AP - not the BSSID


def test_frame_bssid_management_frame_uses_addr3():
    from scapy.all import Dot11
    from wifimonitor.capture import MonitorService

    pkt = Dot11(type=0, subtype=8, FCfield=0, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID)
    assert MonitorService._frame_bssid(pkt) == BSSID


def test_frame_bssid_station_uplink_uses_addr1_not_addr3():
    """ToDS=1 (station -> AP): addr3 is the frame's real destination beyond

    the AP, not the BSSID. The BSSID is addr1.
    """
    from scapy.all import Dot11
    from wifimonitor.capture import MonitorService

    pkt = Dot11(type=2, subtype=0, FCfield=_TO_DS, addr1=BSSID, addr2=STATION, addr3=FAR_SIDE)
    assert MonitorService._frame_bssid(pkt) == BSSID
    assert MonitorService._frame_bssid(pkt) != pkt.addr3


def test_frame_bssid_ap_downlink_uses_addr2_not_addr3():
    """FromDS=1 (AP -> station): addr3 is the frame's original source beyond

    the AP, not the BSSID. The BSSID is addr2.
    """
    from scapy.all import Dot11
    from wifimonitor.capture import MonitorService

    pkt = Dot11(type=2, subtype=0, FCfield=_FROM_DS, addr1=STATION, addr2=BSSID, addr3=FAR_SIDE)
    assert MonitorService._frame_bssid(pkt) == BSSID
    assert MonitorService._frame_bssid(pkt) != pkt.addr3


def test_handle_packet_data_frame_station_gets_correct_bssid(monitor_service):
    """Regression test for the addr3 misattribution bug: a station seen only

    via an ordinary (non-EAPOL) uplink data frame must be recorded with the
    real BSSID, not the frame's far-side destination address.
    """
    from scapy.all import Dot11
    svc, _, _ = monitor_service
    seen = []
    svc.on_station = lambda station: seen.append(station)

    pkt = Dot11(type=2, subtype=0, FCfield=_TO_DS, addr1=BSSID, addr2=STATION, addr3=FAR_SIDE)
    svc._handle_packet(pkt)

    assert len(seen) == 1
    assert seen[0].mac == STATION
    assert seen[0].associated_bssid == BSSID
