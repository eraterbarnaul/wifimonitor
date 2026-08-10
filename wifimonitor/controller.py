"""Qt controller that bridges the EventBus to pyqtSignals.

This is a thin adapter: all logic lives in MonitorUseCase. The controller
simply subscribes to events and re-emits them as Qt signals for the UI.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from PyQt5.QtCore import QObject, pyqtSignal

from .events import EventBus, Events
from .models import AccessPoint, Handshake, Station
from .usecases import MonitorUseCase


class WifiMonitorController(QObject):
    """Qt-aware wrapper around MonitorUseCase. Bridges events → pyqtSignals."""

    access_point_discovered = pyqtSignal(dict)
    station_discovered = pyqtSignal(dict)
    handshake_captured = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    interface_ready = pyqtSignal(str)
    interface_list_changed = pyqtSignal(list)
    deauth_state_changed = pyqtSignal(bool)
    log_generated = pyqtSignal(str)
    security_alert = pyqtSignal(str)
    probe_discovered = pyqtSignal(dict)
    wps_state_changed = pyqtSignal(bool)
    wps_cracked = pyqtSignal(dict)
    crack_state_changed = pyqtSignal(bool)
    crack_cracked = pyqtSignal(dict)
    auto_attack_progress = pyqtSignal(str, str)
    auto_attack_complete = pyqtSignal(bool, str)

    def __init__(self, db_path: Path, capture_dir: Path) -> None:
        super().__init__()
        self.bus = EventBus()
        self._uc = MonitorUseCase(db_path=db_path, capture_dir=capture_dir, bus=self.bus)
        self._connect_events()

    def _connect_events(self) -> None:
        self.bus.subscribe(Events.ACCESS_POINT_DISCOVERED, self.access_point_discovered.emit)
        self.bus.subscribe(Events.STATION_DISCOVERED, self.station_discovered.emit)
        self.bus.subscribe(Events.HANDSHAKE_CAPTURED, self.handshake_captured.emit)
        self.bus.subscribe(Events.STATUS_CHANGED, self.status_changed.emit)
        self.bus.subscribe(Events.INTERFACE_READY, self.interface_ready.emit)
        self.bus.subscribe(Events.INTERFACE_LIST_CHANGED, self.interface_list_changed.emit)
        self.bus.subscribe(Events.DEAUTH_STATE_CHANGED, self.deauth_state_changed.emit)
        self.bus.subscribe(Events.LOG_GENERATED, self.log_generated.emit)
        self.bus.subscribe(Events.SECURITY_ALERT, self.security_alert.emit)
        self.bus.subscribe(Events.PROBE_DISCOVERED, self.probe_discovered.emit)
        self.bus.subscribe(Events.WPS_STATE_CHANGED, self.wps_state_changed.emit)
        self.bus.subscribe(Events.WPS_CRACKED, self.wps_cracked.emit)
        self.bus.subscribe(Events.CRACK_STATE_CHANGED, self.crack_state_changed.emit)
        self.bus.subscribe(Events.CRACK_CRACKED, self.crack_cracked.emit)
        self.bus.subscribe(Events.AUTO_ATTACK_PROGRESS, lambda p, m: self.auto_attack_progress.emit(p, m))
        self.bus.subscribe(Events.AUTO_ATTACK_COMPLETE, lambda ok, m: self.auto_attack_complete.emit(ok, m))

    # Delegate all public API to the use-case layer

    @property
    def db(self):
        return self._uc.db

    @property
    def access_points(self):
        return self._uc.access_points

    @property
    def clients_by_ap(self):
        return self._uc.clients_by_ap

    @property
    def probes_by_client(self):
        return self._uc.probes_by_client

    @property
    def monitor_service(self):
        return self._uc.monitor_service

    @property
    def deauth_service(self):
        return self._uc.deauth_service

    @property
    def current_interface(self):
        return self._uc.current_interface

    @property
    def base_interface(self):
        return self._uc.base_interface

    def set_interface(self, interface: str) -> None:
        self._uc.set_interface(interface)

    def set_secondary_interface(self, interface: str) -> None:
        self._uc.set_secondary_interface(interface)

    def enable_monitor_mode(self) -> None:
        self._uc.enable_monitor_mode()

    def disable_monitor_mode(self) -> None:
        self._uc.disable_monitor_mode()

    def start_capture(self) -> None:
        self._uc.start_capture()

    def stop_capture(self) -> None:
        self._uc.stop_capture()

    def export_hashcat(self, capture_path: Path, output_path: Path, tool_path: Optional[str] = None) -> None:
        self._uc.export_hashcat(capture_path, output_path, tool_path)

    def export_excel(self, output_path: Path) -> None:
        self._uc.export_excel(output_path)

    def export_csv(self, output_path: Path) -> Path:
        return self._uc.export_csv(output_path)

    def export_report(self, output_path: Path) -> None:
        self._uc.export_report(output_path)

    def refresh_interfaces(self) -> List[str]:
        return self._uc.refresh_interfaces()

    def get_clients_for_ap(self, bssid: str) -> List[str]:
        return self._uc.get_clients_for_ap(bssid)

    def start_deauth(self, bssid: str, clients: List[str], packets: int, interval: float) -> None:
        self._uc.start_deauth(bssid, clients, packets, interval)

    def stop_deauth(self) -> None:
        self._uc.stop_deauth()

    def start_auto_attack(self, bssid: str, clients: List[str], channel: Optional[int] = None,
                          essid: Optional[str] = None) -> None:
        self._uc.start_auto_attack(bssid, clients, channel, essid)

    def stop_auto_attack(self) -> None:
        self._uc.stop_auto_attack()

    def start_wps_attack(self, bssid: str, channel: Optional[int]) -> None:
        self._uc.start_wps_attack(bssid, channel)

    def stop_wps_attack(self) -> None:
        self._uc.stop_wps_attack()

    def start_crack(self, capture_path: str, bssid: str, wordlist: str) -> None:
        self._uc.start_crack(capture_path, bssid, wordlist)

    def stop_crack(self) -> None:
        self._uc.stop_crack()

    def request_pmkid(self, bssid: str) -> None:
        self._uc.request_pmkid(bssid)

    def lock_monitor_channel(self, channel: int) -> bool:
        return self._uc.lock_monitor_channel(channel)

    def unlock_monitor_channel(self) -> None:
        self._uc.unlock_monitor_channel()

    def load_access_points(self) -> List[dict]:
        return self._uc.load_access_points()

    def load_stations(self) -> List[dict]:
        return self._uc.load_stations()

    def load_handshakes(self) -> List[dict]:
        return self._uc.load_handshakes()
