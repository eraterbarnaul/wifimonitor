"""Tests for the GPS reader."""
from unittest.mock import patch
from wifimonitor.gps import GpsReader


def test_available_false_when_no_gpsd():
    gps = GpsReader(host="127.0.0.1", port=19999)
    assert gps.available is False


def test_start_returns_false_when_unavailable():
    gps = GpsReader(host="127.0.0.1", port=19999)
    result = gps.start()
    assert result is False


def test_current_position_none_initially():
    gps = GpsReader()
    assert gps.current_position() is None


@patch("socket.create_connection")
def test_available_true_when_gpsd_running(mock_conn):
    mock_conn.return_value.close = lambda: None
    gps = GpsReader()
    assert gps.available is True
