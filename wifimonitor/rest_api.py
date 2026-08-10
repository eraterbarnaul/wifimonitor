"""Minimal REST API for remote control (headless Raspberry Pi scenario).

Uses only the stdlib (http.server) to avoid adding flask/fastapi as a
dependency. For production use, consider wrapping with a proper ASGI framework.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .usecases import MonitorUseCase


class ApiHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the REST API."""

    use_case: Optional[MonitorUseCase] = None

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _json_response(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json_response({"error": message}, status)

    def _serve_web_ui(self) -> None:
        """Serve the built-in web UI HTML page."""
        ui_path = Path(__file__).parent / "ui" / "web" / "index.html"
        if not ui_path.exists():
            self._error(404, "Web UI not found")
            return
        body = ui_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def do_GET(self) -> None:
        uc = self.use_case
        if not uc:
            self._error(503, "Not initialized")
            return

        path = urlparse(self.path).path.rstrip("/")

        if path == "/api/status":
            self._json_response({
                "interface": uc.current_interface,
                "base_interface": uc.base_interface,
                "monitoring": uc.monitor_service is not None and uc.monitor_service.is_running(),
                "ap_count": len(uc.access_points),
            })
        elif path == "/api/access_points":
            with uc._state_lock:
                aps = [
                    {
                        "bssid": ap.bssid,
                        "essid": ap.essid,
                        "channel": ap.channel,
                        "encryption": ap.encryption,
                        "signal": ap.signal,
                        "wps": ap.wps,
                        "mfp_required": ap.mfp_required,
                        "bandwidth": ap.bandwidth,
                        "wifi_generation": ap.wifi_generation,
                    }
                    for ap in uc.access_points.values()
                ]
            self._json_response(aps)
        elif path == "/api/stations":
            rows = [dict(r) for r in uc.db.fetch_stations()]
            self._json_response(rows)
        elif path == "/api/handshakes":
            rows = [dict(r) for r in uc.db.fetch_handshakes()]
            self._json_response(rows)
        elif path == "/api/interfaces":
            interfaces = uc.interface_manager.list_wireless_interfaces()
            self._json_response(interfaces)
        elif path == "/api/sessions":
            rows = [dict(r) for r in uc.db.fetch_sessions()]
            self._json_response(rows)
        elif path == "" or path == "/" or path == "/index.html":
            self._serve_web_ui()
        else:
            self._error(404, f"Not found: {path}")

    def do_POST(self) -> None:
        uc = self.use_case
        if not uc:
            self._error(503, "Not initialized")
            return

        path = urlparse(self.path).path.rstrip("/")

        try:
            if path == "/api/start":
                body = self._read_body()
                interface = body.get("interface")
                if interface:
                    uc.set_interface(interface)
                uc.start_capture()
                self._json_response({"status": "started"})
            elif path == "/api/stop":
                uc.stop_capture()
                self._json_response({"status": "stopped"})
            elif path == "/api/deauth":
                body = self._read_body()
                bssid = body.get("bssid", "")
                clients = body.get("clients", [])
                packets = body.get("packets", 5)
                interval = body.get("interval", 1.0)
                uc.start_deauth(bssid, clients, packets, interval)
                self._json_response({"status": "deauth_started"})
            elif path == "/api/deauth/stop":
                uc.stop_deauth()
                self._json_response({"status": "deauth_stopped"})
            elif path == "/api/auto_attack":
                body = self._read_body()
                bssid = body.get("bssid", "")
                clients = body.get("clients", [])
                channel = body.get("channel")
                essid = body.get("essid")
                uc.start_auto_attack(bssid, clients, channel, essid)
                self._json_response({"status": "auto_attack_started"})
            elif path == "/api/auto_attack/stop":
                uc.stop_auto_attack()
                self._json_response({"status": "auto_attack_stopped"})
            else:
                self._error(404, f"Not found: {path}")
        except Exception as exc:  # noqa: BLE001
            self._error(400, str(exc))


class RestApiServer:
    """Lightweight REST API server for remote monitoring."""

    def __init__(self, use_case: MonitorUseCase, host: str = "0.0.0.0", port: int = 8080) -> None:
        self._uc = use_case
        self._host = host
        self._port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        ApiHandler.use_case = self._uc
        self._server = HTTPServer((self._host, self._port), ApiHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"
