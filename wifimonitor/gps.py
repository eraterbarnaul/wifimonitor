"""GPS integration for wardriving and AP geolocation.

Connects to gpsd (the GPS daemon) to read real-time position data.
Falls back gracefully when gpsd is unavailable.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Callable, Optional

from .models import GpsCoordinate
from .timeutil import utcnow


class GpsReader:
    """Reads GPS data from gpsd via its JSON protocol (port 2947).

    Usage:
        gps = GpsReader()
        gps.start()
        coord = gps.current_position()  # may be None if no fix
        gps.stop()
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2947,
        on_fix: Optional[Callable[[GpsCoordinate], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._on_fix = on_fix
        self._log = on_log
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._current: Optional[GpsCoordinate] = None
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        """Check if gpsd is reachable."""
        try:
            sock = socket.create_connection((self._host, self._port), timeout=2)
            sock.close()
            return True
        except (OSError, ConnectionRefusedError):
            return False

    def start(self) -> bool:
        """Start reading GPS data. Returns False if gpsd is unreachable."""
        if not self.available:
            if self._log:
                self._log("GPS: gpsd не доступен, геолокация отключена")
            return False
        self._running.set()
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()
        if self._log:
            self._log("GPS: подключение к gpsd")
        return True

    def stop(self) -> None:
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None

    def current_position(self) -> Optional[GpsCoordinate]:
        """Return the last known GPS position, or None if no fix."""
        with self._lock:
            return self._current

    def _reader_loop(self) -> None:
        while self._running.is_set():
            try:
                sock = socket.create_connection((self._host, self._port), timeout=5)
                sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
                buffer = ""
                while self._running.is_set():
                    try:
                        data = sock.recv(4096).decode("utf-8", errors="ignore")
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    buffer += data
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        self._process_line(line.strip())
                sock.close()
            except (OSError, ConnectionRefusedError) as exc:
                if self._log:
                    self._log(f"GPS: ошибка подключения: {exc}")
                time.sleep(5)  # Retry after delay

    def _process_line(self, line: str) -> None:
        if not line:
            return
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return
        if msg.get("class") != "TPV":
            return
        mode = msg.get("mode", 0)
        if mode < 2:  # No fix
            return
        lat = msg.get("lat")
        lon = msg.get("lon")
        if lat is None or lon is None:
            return
        coord = GpsCoordinate(
            latitude=float(lat),
            longitude=float(lon),
            altitude=msg.get("altHAE") or msg.get("alt"),
            accuracy=msg.get("epx"),
            timestamp=utcnow(),
        )
        with self._lock:
            self._current = coord
        if self._on_fix:
            self._on_fix(coord)
