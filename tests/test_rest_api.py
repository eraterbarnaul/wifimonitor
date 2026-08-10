"""Tests for the REST API server."""
import json
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture
def api_server(tmp_path):
    """Start a REST API server on a random port."""
    with patch("wifimonitor.usecases.InterfaceManager") as MockIM, \
         patch("wifimonitor.usecases.GpsReader"):
        mock_im = MockIM.return_value
        mock_im.list_wireless_interfaces.return_value = ["wlan0"]
        mock_im.ensure_monitor_mode.return_value = "wlan0mon"
        mock_im.get_injection_interface.return_value = "wlan0mon"

        from wifimonitor.events import EventBus
        from wifimonitor.usecases import MonitorUseCase
        from wifimonitor.rest_api import RestApiServer

        bus = EventBus()
        uc = MonitorUseCase(db_path=tmp_path / "api.db", capture_dir=tmp_path / "caps", bus=bus)
        uc.interface_manager = mock_im

        server = RestApiServer(uc, host="127.0.0.1", port=0)
        # Use port 0 to get random free port — but stdlib HTTPServer doesn't
        # support this well, so use a fixed test port
        server = RestApiServer(uc, host="127.0.0.1", port=18932)
        server.start()
        time.sleep(0.3)
        yield server, uc
        server.stop()


def _get(path, port=18932):
    url = f"http://127.0.0.1:{port}{path}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _post(path, data=None, port=18932):
    url = f"http://127.0.0.1:{port}{path}"
    body = json.dumps(data or {}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def test_status_endpoint(api_server):
    server, uc = api_server
    data = _get("/api/status")
    assert "monitoring" in data
    assert data["ap_count"] == 0


def test_access_points_empty(api_server):
    server, uc = api_server
    data = _get("/api/access_points")
    assert data == []


def test_handshakes_empty(api_server):
    server, uc = api_server
    data = _get("/api/handshakes")
    assert data == []


def test_interfaces(api_server):
    server, uc = api_server
    data = _get("/api/interfaces")
    assert "wlan0" in data


def test_sessions_empty(api_server):
    server, uc = api_server
    data = _get("/api/sessions")
    assert data == []


def test_web_ui_served(api_server):
    """The root path should serve the HTML web UI."""
    server, uc = api_server
    url = f"http://127.0.0.1:18932/"
    with urllib.request.urlopen(url, timeout=5) as resp:
        html = resp.read().decode()
        assert "Wifimonitor" in html
        assert "<table" in html
