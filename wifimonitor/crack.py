"""Offline dictionary cracking of captured handshakes via aircrack-ng.

Runs aircrack-ng as a subprocess against a saved pcap and a wordlist, streaming
progress and reporting a recovered key. The output parser is pure so it can be
unit tested. For authorised testing only.
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
from typing import Callable, List, Optional

log = logging.getLogger("wifimonitor.crack")

_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")
_PROGRESS_RE = re.compile(r"([\d,]+)\s*/\s*([\d,]+)\s+keys tested", re.IGNORECASE)


def parse_aircrack_output(line: str) -> Optional[dict]:
    """Extract a recovered key or a progress update from one aircrack-ng line."""
    found = _KEY_FOUND_RE.search(line)
    if found:
        return {"key": found.group(1)}
    progress = _PROGRESS_RE.search(line)
    if progress:
        tested = int(progress.group(1).replace(",", ""))
        total = int(progress.group(2).replace(",", ""))
        pct = (tested / total * 100) if total else 0.0
        return {"progress": f"{tested}/{total} ({pct:.1f}%)"}
    return None


class CrackService:
    def __init__(
        self,
        log_callback: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[str], None]] = None,
        on_result: Optional[Callable[[dict], None]] = None,
        tool: str = "aircrack-ng",
    ) -> None:
        self.tool = tool
        self._log = log_callback
        self._on_progress = on_progress
        self._on_result = on_result
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _build_command(self, capture_path: str, bssid: str, wordlist: str) -> List[str]:
        return [self.tool, "-w", wordlist, "-b", bssid, capture_path]

    def start(self, capture_path: str, bssid: str, wordlist: str) -> None:
        if self.is_running():
            self.stop()
        self._stop.clear()
        command = self._build_command(capture_path, bssid, wordlist)
        try:
            self._proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"Утилита '{self.tool}' не найдена. Установите aircrack-ng."
            ) from exc
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        if self._log:
            self._log(f"Крекинг запущен ({self.tool}) для {bssid} по словарю {wordlist}")

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
            parsed = parse_aircrack_output(line)
            if not parsed:
                continue
            if "key" in parsed:
                if self._log:
                    self._log(f"Пароль найден: {parsed['key']}")
                if self._on_result:
                    self._on_result(parsed)
            elif "progress" in parsed and self._on_progress:
                self._on_progress(parsed["progress"])
        if self._log and not self._stop.is_set():
            self._log("Крекинг завершён")

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:  # noqa: BLE001 - process may already be gone
                log.debug("terminating hashcat failed", exc_info=True)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._proc = None
        self._thread = None

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
