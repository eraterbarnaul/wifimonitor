from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from PyQt5.QtCore import QObject, pyqtSignal

from .capture import MonitorService
from .database import DatabaseManager
from .exporters import ExcelExporter, HashcatExporter
from .deauth import DeauthService
from .interface import InterfaceManager
from .models import AccessPoint, Handshake, Station


class WifiMonitorController(QObject):
    access_point_discovered = pyqtSignal(dict)
    station_discovered = pyqtSignal(dict)
    handshake_captured = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    interface_ready = pyqtSignal(str)
    interface_list_changed = pyqtSignal(list)
    deauth_state_changed = pyqtSignal(bool)
    log_generated = pyqtSignal(str)

    def __init__(self, db_path: Path, capture_dir: Path) -> None:
        super().__init__()
        self.db = DatabaseManager(db_path)
        self.capture_dir = capture_dir
        self.interface_manager = InterfaceManager()
        self.monitor_service: Optional[MonitorService] = None
        self.hashcat_exporter = HashcatExporter()
        self.excel_exporter = ExcelExporter()
        self.current_interface: Optional[str] = None
        self.base_interface: Optional[str] = None
        self.access_points: Dict[str, AccessPoint] = {}
        self.clients_by_ap: Dict[str, Set[str]] = defaultdict(set)
        self.deauth_service: Optional[DeauthService] = None
        self._log("Контроллер инициализирован")

    def set_interface(self, interface: str) -> None:
        self.base_interface = interface
        self.current_interface = interface
        self.interface_manager.set_base_interface(interface)
        self.status_changed.emit(f"Базовый интерфейс: {interface}")
        self.interface_ready.emit(interface)
        self._log(f"Выбран интерфейс {interface}")

    def enable_monitor_mode(self) -> None:
        monitor_interface = self._ensure_monitor_interface()
        self.status_changed.emit(f"Мониторный режим активирован ({monitor_interface})")
        self._log(f"Мониторный режим активирован на {monitor_interface}")

    def disable_monitor_mode(self) -> None:
        self.interface_manager.disable_monitor_mode()
        self.current_interface = self.base_interface
        if self.base_interface:
            self.interface_ready.emit(self.base_interface)
        self.status_changed.emit("Мониторный режим остановлен")
        self._log("Мониторный режим остановлен")

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
        )
        self.monitor_service.start()
        self.status_changed.emit("Захват запущен")
        self._log(f"Запуск пассивного сканирования на {monitor_interface}")

    def stop_capture(self) -> None:
        if self.monitor_service:
            self.monitor_service.stop()
            self.monitor_service = None
        self.stop_deauth()
        try:
            self.interface_manager.disable_monitor_mode()
        except Exception as exc:  # noqa: BLE001
            self.status_changed.emit(f"Не удалось отключить мониторный режим автоматически: {exc}")
        else:
            self.current_interface = self.base_interface
            if self.base_interface:
                self.interface_ready.emit(self.base_interface)
        self.status_changed.emit("Захват остановлен")
        self._log("Захват остановлен")

    def _handle_access_point(self, ap: AccessPoint) -> None:
        self.db.upsert_access_point(ap)
        self.access_points[ap.bssid] = ap
        self.access_point_discovered.emit(asdict(ap))

    def _handle_station(self, station: Station) -> None:
        self.db.upsert_station(station)
        if station.associated_bssid:
            self.clients_by_ap[station.associated_bssid].add(station.mac)
        self.station_discovered.emit(asdict(station))

    def _handle_handshake(self, handshake: Handshake) -> None:
        self.db.add_handshake(handshake)
        self.handshake_captured.emit(asdict(handshake))

    def export_hashcat(self, capture_path: Path, output_path: Path, tool_path: Optional[str] = None) -> None:
        exporter = self.hashcat_exporter
        if tool_path:
            exporter = HashcatExporter(tool_path=tool_path)
        exporter.export(capture_path, output_path)

    def export_excel(self, output_path: Path) -> None:
        access_points = [dict(row) for row in self.db.fetch_access_points()]
        stations = [dict(row) for row in self.db.fetch_stations()]
        handshakes = [dict(row) for row in self.db.fetch_handshakes()]
        self.excel_exporter.export(output_path, access_points, stations, handshakes)


    def refresh_interfaces(self) -> List[str]:
        interfaces = self.interface_manager.list_wireless_interfaces()
        self.interface_list_changed.emit(interfaces)
        if interfaces and not self.base_interface:
            self.set_interface(interfaces[0])
        if interfaces:
            self._log(f"Найдены беспроводные интерфейсы: {', '.join(interfaces)}")
        else:
            self._log("Беспроводные интерфейсы не найдены")
        return interfaces

    def get_clients_for_ap(self, bssid: str) -> List[str]:
        return sorted(self.clients_by_ap.get(bssid, set()))

    def start_deauth(self, bssid: str, clients: List[str], packets: int, interval: float) -> None:
        if not clients:
            raise ValueError("Для выбранной точки доступа нет активных клиентов")
        monitor_interface = self._ensure_monitor_interface()
        if not self.monitor_service or not self.monitor_service.is_running():
            raise RuntimeError("Запустите мониторинг перед деаутентификацией")
        if not self.deauth_service or self.deauth_service.interface != monitor_interface:
            if self.deauth_service:
                self.deauth_service.stop()
            self.deauth_service = DeauthService(monitor_interface, log_callback=self._log)
        ap = self.access_points.get(bssid)
        locked_channel = None
        if ap and ap.channel:
            if self.monitor_service.lock_channel(ap.channel):
                locked_channel = ap.channel
        self.deauth_service.start(bssid, clients, packets, interval)
        self.deauth_state_changed.emit(True)
        label = ap.essid if ap and ap.essid else bssid
        if locked_channel is not None:
            self._log(f"Мониторинг зафиксирован на канале {locked_channel} для деаутентификации")
        self.status_changed.emit(f"Запущена деаутентификация для {label}")
        client_list = ", ".join(clients)
        self._log(
            f"Деаутентификация запущена для {label}: {len(clients)} клиентов, {packets} пакетов, интервал {interval:.2f} с ({client_list})"
        )

    def stop_deauth(self) -> None:
        if not self.deauth_service:
            return
        was_running = self.deauth_service.is_running()
        self.deauth_service.stop()
        if was_running:
            if self.monitor_service:
                self.monitor_service.unlock_channel()
            self.deauth_state_changed.emit(False)
            self.status_changed.emit("Деаутентификация остановлена")
            self._log("Деаутентификация остановлена")

    def _ensure_monitor_interface(self) -> str:
        if not self.base_interface:
            raise ValueError("Не выбран интерфейс")
        monitor_interface = self.interface_manager.ensure_monitor_mode(self.base_interface)
        self.current_interface = monitor_interface
        self.interface_ready.emit(monitor_interface)
        return monitor_interface

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
                last_seen=datetime.fromisoformat(last_seen) if last_seen else datetime.utcnow(),
            )
            self.access_points[ap.bssid] = ap
        return rows

    def load_stations(self) -> List[dict]:
        rows = [dict(row) for row in self.db.fetch_stations()]
        for row in rows:
            bssid = row.get("associated_bssid")
            mac = row.get("mac")
            if bssid and mac:
                self.clients_by_ap[bssid].add(mac)
        return rows

    def load_handshakes(self) -> List[dict]:
        return [dict(row) for row in self.db.fetch_handshakes()]

    def _log(self, message: str) -> None:
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        self.log_generated.emit(f"[{timestamp}] {message}")
