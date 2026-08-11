"""Minimal REST API for remote control (headless Raspberry Pi scenario).

Uses only the stdlib (http.server) to avoid adding flask/fastapi as a
dependency. For production use, consider wrapping with a proper ASGI framework.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .auth import check_token
from .plugins import registry
from .usecases import MonitorUseCase

# POST bodies are tiny JSON control messages; refuse anything absurdly large
# instead of buffering an attacker-supplied Content-Length into memory.
_MAX_BODY_BYTES = 1_048_576  # 1 MiB


class BodyTooLarge(Exception):
    pass


class ApiHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the REST API."""

    use_case: Optional[MonitorUseCase] = None
    auth_token: str = ""  # when set, requests must present it

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _authorized(self) -> bool:
        query_token = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        if check_token(self.auth_token, self.headers.get("Authorization", ""), query_token):
            return True
        self._error(401, "Unauthorized")
        return False

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
        if length > _MAX_BODY_BYTES:
            raise BodyTooLarge(f"request body of {length} bytes exceeds the {_MAX_BODY_BYTES}-byte limit")
        raw = self.rfile.read(length)
        return json.loads(raw)

    def do_GET(self) -> None:
        uc = self.use_case
        if not uc:
            self._error(503, "Not initialized")
            return

        path = urlparse(self.path).path.rstrip("/")

        # The dashboard shell carries no data of its own (it fetches everything
        # from the JSON endpoints below), so it's served without a token; every
        # endpoint it calls still enforces auth.
        if path == "" or path == "/" or path == "/index.html":
            self._serve_web_ui()
            return

        if not self._authorized():
            return

        if path == "/api/plugins":
            self._json_response(registry.list_plugins())
            return
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
        else:
            self._error(404, f"Not found: {path}")

    def do_POST(self) -> None:
        uc = self.use_case
        if not uc:
            self._error(503, "Not initialized")
            return
        if not self._authorized():
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
        except BodyTooLarge as exc:
            self._error(413, str(exc))
        except Exception as exc:  # noqa: BLE001
            self._error(400, str(exc))


class RestApiServer:
    """Lightweight REST API server for remote monitoring."""

    def __init__(
        self,
        use_case: MonitorUseCase,
        host: str = "127.0.0.1",
        port: int = 8080,
        token: str = "",
    ) -> None:
        self._uc = use_case
        self._host = host
        self._port = port
        self._token = token
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        ApiHandler.use_case = self._uc
        ApiHandler.auth_token = self._token
        if self._host not in ("127.0.0.1", "localhost", "::1") and not self._token:
            logging.getLogger("wifimonitor").warning(
                "REST API слушает %s без токена — доступ к управлению и данным открыт всем в сети",
                self._host,
            )
        self._server = ThreadingHTTPServer((self._host, self._port), ApiHandler)
        self._server.daemon_threads = True
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
