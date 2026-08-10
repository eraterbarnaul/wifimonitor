"""Shared use-case layer that works for both CLI and GUI.

This module provides the core application logic decoupled from Qt.
The WifiMonitorController (Qt) and CLI both delegate to these use-cases.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from .auto_attack import AutoAttackPipeline
from .capture import MonitorService
from .crack import CrackService
from .csv_export import CsvExporter
from .database import DatabaseManager
from .deauth import DeauthService
from .events import EventBus, Events
from .exporters import ExcelExporter, HashcatExporter
from .gps import GpsReader
from .interface import InterfaceManager
from .models import AccessPoint, Handshake, Station
from .pmkid_request import request_pmkid
from .timeutil import as_utc, utcnow
from .wps_attack import WpsAttackService


class MonitorUseCase:
    """Core application logic, independent of Qt.

    Emits events through an EventBus that can be consumed by any frontend
    (Qt adapter, CLI, REST API).
    """

    def __init__(self, db_path: Path, capture_dir: Path, bus: Optional[EventBus] = None) -> None:
        self.bus = bus or EventBus()
        self.db = DatabaseManager(db_path)
        self.capture_dir = capture_dir
        self.interface_manager = InterfaceManager()
        self.monitor_service: Optional[MonitorService] = None
        self.hashcat_exporter = HashcatExporter()
        self.excel_exporter = ExcelExporter()
        self.csv_exporter = CsvExporter()
        self.current_interface: Optional[str] = None
        self.base_interface: Optional[str] = None
        self.access_points: Dict[str, AccessPoint] = {}
        self.clients_by_ap: Dict[str, Set[str]] = defaultdict(set)
        self.probes_by_client: Dict[str, Set[str]] = defaultdict(set)
        self._state_lock = threading.Lock()
        self.deauth_service: Optional[DeauthService] = None
        self.wps_service: Optional[WpsAttackService] = None
        self.crack_service: Optional[CrackService] = None
        self.auto_attack: Optional[AutoAttackPipeline] = None
        self.gps_reader: Optional[GpsReader] = None
        self._session_id: Optional[int] = None
        self._log("Контроллер инициализирован")

    def set_interface(self, interface: str) -> None:
        self.base_interface = interface
        self.current_interface = interface
        self.interface_manager.set_base_interface(interface)
        self.bus.emit(Events.STATUS_CHANGED, f"Базовый интерфейс: {interface}")
        self.bus.emit(Events.INTERFACE_READY, interface)
        self._log(f"Выбран интерфейс {interface}")

    def set_secondary_interface(self, interface: str) -> None:
        self.interface_manager.set_secondary_interface(interface)
        self._log(f"Вторичный интерфейс (injection): {interface}")

    def enable_monitor_mode(self) -> None:
        monitor_interface = self._ensure_monitor_interface()
        self.bus.emit(Events.STATUS_CHANGED, f"Мониторный режим активирован ({monitor_interface})")
        self._log(f"Мониторный режим активирован на {monitor_interface}")

    def disable_monitor_mode(self) -> None:
        self.interface_manager.disable_monitor_mode()
        self.current_interface = self.base_interface
        if self.base_interface:
            self.bus.emit(Events.INTERFACE_READY, self.base_interface)
        self.bus.emit(Events.STATUS_CHANGED, "Мониторный режим остановлен")

    def start_capture(self) -> None:
        if not self.base_interface:
            raise ValueError("Не выбран интерфейс")
        monitor_interface = self._ensure_monitor_interface()
        if self.monitor_service:
            self.monitor_service.stop()
        self.monitor_service = MonitorService(
            interface=monitor_interface,
            capture_dir=self.capture_dir,
            on_access_point=self._handle_access_point,
            on_station=self._handle_station,
            on_handshake=self._handle_handshake,
            on_log=self._log,
            on_alert=self._handle_alert,
            on_probe=self._handle_probe,
            on_ssid_reveal=self._handle_ssid_reveal,
        )
        self.monitor_service.start()
        # Start GPS if available
        self._start_gps()
        # Create session
        self._session_id = self.db.create_session(monitor_interface)
        self.bus.emit(Events.STATUS_CHANGED, "Захват запущен")
        self._log(f"Запуск пассивного сканирования на {monitor_interface}")

    def stop_capture(self) -> None:
        if self.monitor_service:
            self.monitor_service.stop()
            self.monitor_service = None
        self.stop_deauth()
        if self.wps_service and self.wps_service.is_running():
            self.stop_wps_attack()
        if self.crack_service and self.crack_service.is_running():
            self.stop_crack()
        if self.auto_attack and self.auto_attack.is_running():
            self.auto_attack.stop()
        if self.gps_reader:
            self.gps_reader.stop()
            self.gps_reader = None
        # End session and snapshot
        if self._session_id:
            aps = [dict(row) for row in self.db.fetch_access_points()]
            stas = [dict(row) for row in self.db.fetch_stations()]
            self.db.snapshot_session(self._session_id, aps, stas)
            self.db.end_session(self._session_id)
            self._session_id = None
        try:
            self.interface_manager.disable_monitor_mode()
        except Exception as exc:  # noqa: BLE001
            self.bus.emit(Events.STATUS_CHANGED, f"Не удалось отключить мониторный режим: {exc}")
        else:
            self.current_interface = self.base_interface
            if self.base_interface:
                self.bus.emit(Events.INTERFACE_READY, self.base_interface)
        self.bus.emit(Events.STATUS_CHANGED, "Захват остановлен")
        self._log("Захват остановлен")

    def _handle_access_point(self, ap: AccessPoint) -> None:
        self.db.upsert_access_point(ap)
        with self._state_lock:
            self.access_points[ap.bssid] = ap
        self.bus.emit(Events.ACCESS_POINT_DISCOVERED, asdict(ap))
        # Record GPS location if available
        self._record_gps_for_ap(ap)

    def _handle_station(self, station: Station) -> None:
        self.db.upsert_station(station)
        if station.associated_bssid:
            with self._state_lock:
                self.clients_by_ap[station.associated_bssid].add(station.mac)
        self.bus.emit(Events.STATION_DISCOVERED, asdict(station))

    def _handle_handshake(self, handshake: Handshake) -> None:
        self.db.add_handshake(handshake)
        self.bus.emit(Events.HANDSHAKE_CAPTURED, asdict(handshake))
        # Notify auto-attack pipeline if running
        if self.auto_attack and self.auto_attack.is_running():
            self.auto_attack.notify_handshake(handshake.capture_path)

    def _handle_alert(self, message: str) -> None:
        if self.deauth_service and self.deauth_service.is_running():
            return
        self._log(f"[ВНИМАНИЕ] {message}")
        self.bus.emit(Events.SECURITY_ALERT, message)

    def _handle_probe(self, mac: str, ssid: str) -> None:
        with self._state_lock:
            self.probes_by_client[mac].add(ssid)
        self.bus.emit(Events.PROBE_DISCOVERED, {"mac": mac, "ssid": ssid})

    def _handle_ssid_reveal(self, bssid: str, ssid: str) -> None:
        with self._state_lock:
            ap = self.access_points.get(bssid)
            reveal = ap is not None and not ap.essid
            if reveal:
                ap.essid = ssid
        if reveal:
            self.db.upsert_access_point_force(ap)
            self.bus.emit(Events.ACCESS_POINT_DISCOVERED, asdict(ap))
            self._log(f"Раскрыт скрытый SSID: {ssid} ({bssid})")

    def export_hashcat(self, capture_path: Path, output_path: Path, tool_path: Optional[str] = None) -> None:
        if tool_path:
            HashcatExporter(tool_path=tool_path).export_with_tool(capture_path, output_path)
        else:
            self.hashcat_exporter.export(capture_path, output_path)

    def export_excel(self, output_path: Path) -> None:
        access_points = [dict(row) for row in self.db.fetch_access_points()]
        stations = [dict(row) for row in self.db.fetch_stations()]
        handshakes = [dict(row) for row in self.db.fetch_handshakes()]
        self.excel_exporter.export(output_path, access_points, stations, handshakes)

    def export_csv(self, output_path: Path) -> Path:
        access_points = [dict(row) for row in self.db.fetch_access_points()]
        stations = [dict(row) for row in self.db.fetch_stations()]
        return self.csv_exporter.export(output_path, access_points, stations)

    def export_report(self, output_path: Path) -> None:
        from .detect import find_evil_twins
        from .report import build_html_report
        access_points = [dict(row) for row in self.db.fetch_access_points()]
        stations = [dict(row) for row in self.db.fetch_stations()]
        handshakes = [dict(row) for row in self.db.fetch_handshakes()]
        gps_locations = [dict(row) for row in self.db.fetch_ap_locations()]
        evil_twins = find_evil_twins(access_points)
        with self._state_lock:
            probes = {mac: sorted(ssids) for mac, ssids in self.probes_by_client.items()}
        html = build_html_report(
            access_points, stations, handshakes,
            probes=probes,
            evil_twins=evil_twins if evil_twins else None,
            gps_locations=gps_locations if gps_locations else None,
        )
        Path(output_path).write_text(html, encoding="utf-8")

    def refresh_interfaces(self) -> List[str]:
        interfaces = self.interface_manager.list_wireless_interfaces()
        self.bus.emit(Events.INTERFACE_LIST_CHANGED, interfaces)
        if interfaces and not self.base_interface:
            self.set_interface(interfaces[0])
        if interfaces:
            self._log(f"Найдены интерфейсы: {', '.join(interfaces)}")
        else:
            self._log("Беспроводные интерфейсы не найдены")
        return interfaces

    def get_clients_for_ap(self, bssid: str) -> List[str]:
        with self._state_lock:
            return sorted(self.clients_by_ap.get(bssid, set()))

    # --- Attack operations ---

    def start_deauth(self, bssid: str, clients: List[str], packets: int, interval: float) -> None:
        if not clients:
            raise ValueError("Нет активных клиентов")
        iface = self.interface_manager.get_injection_interface() or self._ensure_monitor_interface()
        if not self.monitor_service or not self.monitor_service.is_running():
            raise RuntimeError("Запустите мониторинг перед деаутентификацией")
        if not self.deauth_service or self.deauth_service.interface != iface:
            if self.deauth_service:
                self.deauth_service.stop()
            self.deauth_service = DeauthService(iface, log_callback=self._log)
        with self._state_lock:
            ap = self.access_points.get(bssid)
        if ap and ap.channel and self.monitor_service:
            self.monitor_service.lock_channel(ap.channel)
        self.deauth_service.start(bssid, clients, packets, interval)
        self.bus.emit(Events.DEAUTH_STATE_CHANGED, True)

    def stop_deauth(self) -> None:
        if not self.deauth_service:
            return
        was_running = self.deauth_service.is_running()
        self.deauth_service.stop()
        if was_running:
            if self.monitor_service:
                self.monitor_service.unlock_channel()
            self.bus.emit(Events.DEAUTH_STATE_CHANGED, False)

    def start_auto_attack(self, bssid: str, clients: List[str], channel: Optional[int] = None,
                          essid: Optional[str] = None) -> None:
        iface = self.interface_manager.get_injection_interface() or self._ensure_monitor_interface()
        self.auto_attack = AutoAttackPipeline(
            interface=iface,
            capture_dir=self.capture_dir,
            on_progress=lambda phase, msg: self.bus.emit(Events.AUTO_ATTACK_PROGRESS, phase.name, msg),
            on_complete=lambda ok, msg: self.bus.emit(Events.AUTO_ATTACK_COMPLETE, ok, msg),
            log=self._log,
        )
        self.auto_attack.start(bssid, clients, channel, essid)

    def stop_auto_attack(self) -> None:
        if self.auto_attack:
            self.auto_attack.stop()

    def start_wps_attack(self, bssid: str, channel: Optional[int]) -> None:
        iface = self._ensure_monitor_interface()
        if self.wps_service and self.wps_service.is_running():
            self.wps_service.stop()
        self.wps_service = WpsAttackService(
            iface, log_callback=self._log, on_result=self._handle_wps_result
        )
        self.wps_service.start(bssid, channel)
        self.bus.emit(Events.WPS_STATE_CHANGED, True)

    def stop_wps_attack(self) -> None:
        if self.wps_service:
            self.wps_service.stop()
        self.bus.emit(Events.WPS_STATE_CHANGED, False)

    def _handle_wps_result(self, result: dict) -> None:
        self.bus.emit(Events.WPS_CRACKED, result)

    def start_crack(self, capture_path: str, bssid: str, wordlist: str) -> None:
        if self.crack_service and self.crack_service.is_running():
            self.crack_service.stop()
        self.crack_service = CrackService(
            log_callback=self._log,
            on_progress=lambda p: self.bus.emit(Events.STATUS_CHANGED, f"Крекинг: {p}"),
            on_result=self._handle_crack_result,
        )
        self.crack_service.start(capture_path, bssid, wordlist)
        self.bus.emit(Events.CRACK_STATE_CHANGED, True)

    def stop_crack(self) -> None:
        if self.crack_service:
            self.crack_service.stop()
        self.bus.emit(Events.CRACK_STATE_CHANGED, False)

    def _handle_crack_result(self, result: dict) -> None:
        self.bus.emit(Events.CRACK_CRACKED, result)
        self.bus.emit(Events.CRACK_STATE_CHANGED, False)

    def request_pmkid(self, bssid: str) -> None:
        if not self.monitor_service or not self.monitor_service.is_running():
            raise RuntimeError("Запустите мониторинг перед запросом PMKID")
        iface = self._ensure_monitor_interface()
        with self._state_lock:
            ap = self.access_points.get(bssid)
        channel = ap.channel if ap else None
        essid = ap.essid if ap else ""
        if channel and self.monitor_service:
            self.monitor_service.lock_channel(channel)
        request_pmkid(iface, bssid, essid=essid or "", channel=channel, log=self._log)

    def lock_monitor_channel(self, channel: int) -> bool:
        if self.monitor_service and channel:
            return self.monitor_service.lock_channel(int(channel))
        return False

    def unlock_monitor_channel(self) -> None:
        if self.monitor_service:
            self.monitor_service.unlock_channel()

    # --- Data loading ---

    def load_access_points(self) -> List[dict]:
        rows = [dict(row) for row in self.db.fetch_access_points()]
        for row in rows:
            last_seen = row.get("last_seen")
            ap = AccessPoint(
                bssid=row.get("bssid"),
                essid=row.get("essid"),
                channel=row.get("channel"),
                encryption=row.get("encryption"),
                signal=row.get("signal"),
                wps=bool(row.get("wps")),
                mfp_required=bool(row.get("mfp_required")),
                bandwidth=row.get("bandwidth") or "",
                wifi_generation=row.get("wifi_generation") or "",
                last_seen=as_utc(datetime.fromisoformat(last_seen)) if last_seen else utcnow(),
            )
            with self._state_lock:
                self.access_points[ap.bssid] = ap
        return rows

    def load_stations(self) -> List[dict]:
        rows = [dict(row) for row in self.db.fetch_stations()]
        for row in rows:
            bssid = row.get("associated_bssid")
            mac = row.get("mac")
            if bssid and mac:
                with self._state_lock:
                    self.clients_by_ap[bssid].add(mac)
        return rows

    def load_handshakes(self) -> List[dict]:
        return [dict(row) for row in self.db.fetch_handshakes()]

    # --- GPS ---

    def _start_gps(self) -> None:
        self.gps_reader = GpsReader(on_log=self._log)
        if not self.gps_reader.start():
            self.gps_reader = None

    def _record_gps_for_ap(self, ap: AccessPoint) -> None:
        """If GPS is available, record the current position for this AP."""
        if not self.gps_reader:
            return
        coord = self.gps_reader.current_position()
        if coord is None:
            return
        self.db.record_ap_location(
            bssid=ap.bssid,
            latitude=coord.latitude,
            longitude=coord.longitude,
            altitude=coord.altitude,
            signal=ap.signal,
        )

    # --- Helpers ---

    def _ensure_monitor_interface(self) -> str:
        if not self.base_interface:
            raise ValueError("Не выбран интерфейс")
        monitor_interface = self.interface_manager.ensure_monitor_mode(self.base_interface)
        self.current_interface = monitor_interface
        self.bus.emit(Events.INTERFACE_READY, monitor_interface)
        return monitor_interface

    def _log(self, message: str) -> None:
        logging.getLogger("wifimonitor").info(message)
        timestamp = utcnow().strftime("%H:%M:%S")
        self.bus.emit(Events.LOG_GENERATED, f"[{timestamp}] {message}")
