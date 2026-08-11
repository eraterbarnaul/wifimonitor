"""Tests for the REST API server."""
import json
import time
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest


def _make_uc(tmp_path, MockIM):
    mock_im = MockIM.return_value
    mock_im.list_wireless_interfaces.return_value = ["wlan0"]
    mock_im.ensure_monitor_mode.return_value = "wlan0mon"
    mock_im.get_injection_interface.return_value = "wlan0mon"

    from wifimonitor.events import EventBus
    from wifimonitor.usecases import MonitorUseCase

    bus = EventBus()
    uc = MonitorUseCase(db_path=tmp_path / "api.db", capture_dir=tmp_path / "caps", bus=bus)
    uc.interface_manager = mock_im
    return uc


@pytest.fixture
def api_server(tmp_path):
    """Start a REST API server (no auth token) on a fixed test port."""
    with patch("wifimonitor.usecases.InterfaceManager") as MockIM, \
         patch("wifimonitor.usecases.GpsReader"):
        from wifimonitor.rest_api import RestApiServer

        uc = _make_uc(tmp_path, MockIM)
        # stdlib HTTPServer doesn't cooperate well with port 0 here, so use a fixed test port
        server = RestApiServer(uc, host="127.0.0.1", port=18932)
        server.start()
        time.sleep(0.3)
        yield server, uc
        server.stop()


@pytest.fixture
def api_server_with_token(tmp_path):
    """Start a REST API server with a required bearer token, on a separate port."""
    with patch("wifimonitor.usecases.InterfaceManager") as MockIM, \
         patch("wifimonitor.usecases.GpsReader"):
        from wifimonitor.rest_api import RestApiServer

        uc = _make_uc(tmp_path, MockIM)
        server = RestApiServer(uc, host="127.0.0.1", port=18933, token="s3cr3t")
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
    url = "http://127.0.0.1:18932/"
    with urllib.request.urlopen(url, timeout=5) as resp:
        html = resp.read().decode()
        assert "Wifimonitor" in html
        assert "<table" in html


def test_web_ui_served_without_token_even_when_required(api_server_with_token):
    """The dashboard shell itself must load with no token, or nobody could ever

    enter one — only the JSON endpoints it calls need to be authorized.
    """
    with urllib.request.urlopen("http://127.0.0.1:18933/", timeout=5) as resp:
        assert resp.status == 200
        assert "Wifimonitor" in resp.read().decode()


def test_api_rejects_missing_token(api_server_with_token):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get("/api/status", port=18933)
    assert exc.value.code == 401


def test_api_rejects_wrong_token(api_server_with_token):
    req = urllib.request.Request(
        "http://127.0.0.1:18933/api/status", headers={"Authorization": "Bearer wrong"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 401


def test_api_accepts_correct_bearer_token(api_server_with_token):
    req = urllib.request.Request(
        "http://127.0.0.1:18933/api/status", headers={"Authorization": "Bearer s3cr3t"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read())
    assert "monitoring" in data


def test_api_accepts_query_token_fallback(api_server_with_token):
    data = _get("/api/status?token=s3cr3t", port=18933)
    assert "monitoring" in data


def test_post_oversized_body_rejected(api_server):
    """A client claiming a huge Content-Length must be refused, not buffered."""
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", 18932, timeout=5)
    body = json.dumps({"bssid": "AA:BB:CC:DD:EE:FF"}).encode()
    conn.putrequest("POST", "/api/deauth")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(2 * 1024 * 1024))  # lie: body below is tiny
    conn.endheaders()
    conn.send(body)
    resp = conn.getresponse()
    assert resp.status == 413
    conn.close()
