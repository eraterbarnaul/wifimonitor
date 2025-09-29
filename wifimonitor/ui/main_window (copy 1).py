from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QFileDialog,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..controller import WifiMonitorController


class MainWindow(QMainWindow):
    def __init__(self, controller: WifiMonitorController) -> None:
        super().__init__()
        self.controller = controller
        self.setWindowTitle("Wifimonitor")
        self.resize(1200, 800)
        self.ap_records: Dict[str, dict] = {}
        self.clients_map: Dict[str, Set[str]] = defaultdict(set)
        self._setup_ui()
        self._connect_signals()
        self._populate_from_db()
        self._on_deauth_state(False)
        self._refresh_targets()
        self.controller.refresh_interfaces()

    def _setup_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout()

        control_layout = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.interface_combo.setEditable(True)
        self.interface_combo.setPlaceholderText("Выберите интерфейс")
        control_layout.addWidget(QLabel("Интерфейс:"))
        control_layout.addWidget(self.interface_combo)

        self.refresh_interfaces_btn = QPushButton("Обновить")
        self.set_interface_btn = QPushButton("Применить")
        self.enable_monitor_btn = QPushButton("Включить монитор")
        self.disable_monitor_btn = QPushButton("Выключить монитор")
        self.start_capture_btn = QPushButton("Старт")
        self.stop_capture_btn = QPushButton("Стоп")

        for btn in [
            self.refresh_interfaces_btn,
            self.set_interface_btn,
            self.enable_monitor_btn,
            self.disable_monitor_btn,
            self.start_capture_btn,
            self.stop_capture_btn,
        ]:
            control_layout.addWidget(btn)

        layout.addLayout(control_layout)

        self.tabs = QTabWidget()
        monitor_tab = QWidget()
        monitor_layout = QVBoxLayout()
        splitter = QSplitter(Qt.Vertical)

        self.ap_table = QTableWidget(0, 6)
        self.ap_table.setHorizontalHeaderLabels(["BSSID", "ESSID", "Канал", "Шифрование", "Сигнал", "Обновлено"])
        self.ap_table.horizontalHeader().setStretchLastSection(True)
        ap_group = QGroupBox("Точки доступа")
        ap_layout = QVBoxLayout()
        ap_layout.addWidget(self.ap_table)
        ap_group.setLayout(ap_layout)
        splitter.addWidget(ap_group)

        self.st_table = QTableWidget(0, 4)
        self.st_table.setHorizontalHeaderLabels(["MAC", "BSSID", "Сигнал", "Обновлено"])
        self.st_table.horizontalHeader().setStretchLastSection(True)
        st_group = QGroupBox("Клиенты")
        st_layout = QVBoxLayout()
        st_layout.addWidget(self.st_table)
        st_group.setLayout(st_layout)
        splitter.addWidget(st_group)

        monitor_layout.addWidget(splitter)
        monitor_tab.setLayout(monitor_layout)
        self.tabs.addTab(monitor_tab, "Мониторинг")

        handshake_tab = QWidget()
        handshake_layout = QVBoxLayout()

        controls_group = QGroupBox("Настройки deauth-атаки")
        controls_group_layout = QVBoxLayout()
        form_layout = QFormLayout()

        self.target_ap_combo = QComboBox()
        self.target_ap_combo.setPlaceholderText("Выберите точку доступа")
        form_layout.addRow("Точка доступа:", self.target_ap_combo)

        self.target_client_combo = QComboBox()
        self.target_client_combo.setPlaceholderText("Все клиенты")
        form_layout.addRow("Клиент:", self.target_client_combo)

        self.deauth_count_spin = QSpinBox()
        self.deauth_count_spin.setRange(1, 2048)
        self.deauth_count_spin.setValue(10)
        form_layout.addRow("Пакетов на клиента:", self.deauth_count_spin)

        self.deauth_interval_spin = QDoubleSpinBox()
        self.deauth_interval_spin.setDecimals(2)
        self.deauth_interval_spin.setRange(0.0, 60.0)
        self.deauth_interval_spin.setSingleStep(0.1)
        self.deauth_interval_spin.setValue(1.0)
        self.deauth_interval_spin.setSuffix(" с")
        form_layout.addRow("Интервал:", self.deauth_interval_spin)

        controls_group_layout.addLayout(form_layout)
        buttons_layout = QHBoxLayout()
        self.start_deauth_btn = QPushButton("Запустить деаутентификацию")
        self.stop_deauth_btn = QPushButton("Остановить")
        buttons_layout.addWidget(self.start_deauth_btn)
        buttons_layout.addWidget(self.stop_deauth_btn)
        controls_group_layout.addLayout(buttons_layout)
        controls_group.setLayout(controls_group_layout)

        handshake_layout.addWidget(controls_group)

        handshake_group = QGroupBox("Пойманные handshakes")
        handshake_group_layout = QVBoxLayout()
        self.hs_table = QTableWidget(0, 4)
        self.hs_table.setHorizontalHeaderLabels(["BSSID", "Клиент", "Файл", "Создан"])
        self.hs_table.horizontalHeader().setStretchLastSection(True)
        handshake_group_layout.addWidget(self.hs_table)
        handshake_group.setLayout(handshake_group_layout)
        handshake_layout.addWidget(handshake_group)

        handshake_tab.setLayout(handshake_layout)
        self.tabs.addTab(handshake_tab, "Перехват")

        layout.addWidget(self.tabs)

        export_layout = QHBoxLayout()
        self.export_excel_btn = QPushButton("Экспорт Excel")
        self.export_hashcat_btn = QPushButton("Экспорт Hashcat")
        export_layout.addWidget(self.export_excel_btn)
        export_layout.addWidget(self.export_hashcat_btn)
        export_layout.addStretch()
        layout.addLayout(export_layout)

        central.setLayout(layout)
        self.setCentralWidget(central)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def _connect_signals(self) -> None:
        self.set_interface_btn.clicked.connect(self._on_set_interface)
        self.enable_monitor_btn.clicked.connect(self._on_enable_monitor)
        self.disable_monitor_btn.clicked.connect(self._on_disable_monitor)
        self.start_capture_btn.clicked.connect(self._on_start_capture)
        self.stop_capture_btn.clicked.connect(self._on_stop_capture)
        self.export_excel_btn.clicked.connect(self._on_export_excel)
        self.export_hashcat_btn.clicked.connect(self._on_export_hashcat)
        self.refresh_interfaces_btn.clicked.connect(self._on_refresh_interfaces)
        self.start_deauth_btn.clicked.connect(self._on_start_deauth)
        self.stop_deauth_btn.clicked.connect(self._on_stop_deauth)
        self.target_ap_combo.currentIndexChanged.connect(self._on_target_ap_changed)
        self.controller.access_point_discovered.connect(self._add_access_point)
        self.controller.station_discovered.connect(self._add_station)
        self.controller.handshake_captured.connect(self._add_handshake)
        self.controller.status_changed.connect(self.status_bar.showMessage)
        self.controller.interface_ready.connect(self._on_interface_ready)
        self.controller.interface_list_changed.connect(self._populate_interfaces)
        self.controller.deauth_state_changed.connect(self._on_deauth_state)

    def _populate_from_db(self) -> None:
        for ap in self.controller.load_access_points():
            self._add_access_point(ap)
        for station in self.controller.load_stations():
            self._add_station(station)
        for handshake in self.controller.load_handshakes():
            self._add_handshake(handshake)
        self._refresh_targets()

    def _on_set_interface(self) -> None:
        interface = self.interface_combo.currentText().strip()
        if not interface:
            self._show_error("Укажите интерфейс")
            return
        self.controller.set_interface(interface)
        self.status_bar.showMessage(f"Выбран интерфейс {interface}")

    def _on_enable_monitor(self) -> None:
        try:
            self.controller.enable_monitor_mode()
        except Exception as exc:
            self._show_error(str(exc))

    def _on_disable_monitor(self) -> None:
        try:
            self.controller.disable_monitor_mode()
        except Exception as exc:
            self._show_error(str(exc))

    def _on_start_capture(self) -> None:
        try:
            self.controller.start_capture()
        except Exception as exc:
            self._show_error(str(exc))

    def _on_stop_capture(self) -> None:
        try:
            self.controller.stop_capture()
        except Exception as exc:
            self._show_error(str(exc))

    def _on_export_excel(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(self, "Сохранить Excel", "results.xlsx", "Excel (*.xlsx)")
        if not destination:
            return
        try:
            self.controller.export_excel(Path(destination))
            self.status_bar.showMessage("Экспорт Excel выполнен", 5000)
        except Exception as exc:
            self._show_error(str(exc))

    def _on_export_hashcat(self) -> None:
        row = self.hs_table.currentRow()
        if row < 0:
            self._show_error("Выберите handshake")
            return
        capture_path_item = self.hs_table.item(row, 2)
        if not capture_path_item:
            self._show_error("Не найден путь к файлу")
            return
        capture_path = Path(capture_path_item.text())
        destination, _ = QFileDialog.getSaveFileName(self, "Сохранить Hashcat", f"{capture_path.stem}.hc22000", "Hashcat (*.hc22000)")
        if not destination:
            return
        try:
            self.controller.export_hashcat(capture_path, Path(destination))
            self.status_bar.showMessage("Экспорт Hashcat выполнен", 5000)
        except Exception as exc:
            self._show_error(str(exc))

    def _add_access_point(self, ap: dict) -> None:
        bssid = ap["bssid"]
        self.ap_records[bssid] = ap
        self._update_row(self.ap_table, ap["bssid"], [
            self._to_text(ap.get("bssid")),
            self._to_text(ap.get("essid")),
            self._to_text(ap.get("channel")),
            self._to_text(ap.get("encryption")),
            self._to_text(ap.get("signal")),
            self._to_text(ap.get("last_seen")),
        ])
        self._refresh_targets()

    def _add_station(self, station: dict) -> None:
        bssid = station.get("associated_bssid")
        mac = station.get("mac")
        if bssid and mac:
            self.clients_map[bssid].add(mac)
        self._update_row(self.st_table, station["mac"], [
            self._to_text(station.get("mac")),
            self._to_text(station.get("associated_bssid")),
            self._to_text(station.get("signal")),
            self._to_text(station.get("last_seen")),
        ])
        if bssid and mac:
            self._refresh_targets()

    def _add_handshake(self, handshake: dict) -> None:
        key = f"{handshake.get('bssid')}->{handshake.get('station_mac')}"
        self._update_row(self.hs_table, key, [
            self._to_text(handshake.get("bssid")),
            self._to_text(handshake.get("station_mac")),
            self._to_text(handshake.get("capture_path")),
            self._to_text(handshake.get("created_at")),
        ])

    def _update_row(self, table: QTableWidget, key: str, values: List[str]) -> None:
        row = self._find_row(table, key)
        if row is None:
            row = table.rowCount()
            table.insertRow(row)
            key_item = QTableWidgetItem(key)
            key_item.setData(Qt.UserRole, key)
            table.setVerticalHeaderItem(row, key_item)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value or "")
            table.setItem(row, col, item)

    def _to_text(self, value) -> str:
        if value is None:
            return ""
        return str(value)

    def _on_interface_ready(self, interface: str) -> None:
        if not interface:
            return
        current = self.interface_combo.currentText().strip()
        if current == interface:
            return
        idx = self.interface_combo.findText(interface)
        if idx >= 0:
            self.interface_combo.setCurrentIndex(idx)
        else:
            self.interface_combo.setEditText(interface)

    def _refresh_targets(self) -> None:
        current_bssid = self.target_ap_combo.currentData()
        self.target_ap_combo.blockSignals(True)
        self.target_ap_combo.clear()
        for bssid, ap in sorted(self.ap_records.items()):
            clients = sorted(self.clients_map.get(bssid, set()))
            if not clients:
                continue
            essid = ap.get("essid") or bssid
            label = f"{essid} ({bssid}) - {len(clients)} кли." if essid else f"{bssid} - {len(clients)} кли."
            self.target_ap_combo.addItem(label, bssid)
        if current_bssid:
            idx = self.target_ap_combo.findData(current_bssid)
            if idx >= 0:
                self.target_ap_combo.setCurrentIndex(idx)
        self.target_ap_combo.setEnabled(self.target_ap_combo.count() > 0)
        self.target_ap_combo.blockSignals(False)
        self._populate_clients_for_ap(self.target_ap_combo.currentData())

    def _populate_clients_for_ap(self, bssid: Optional[str]) -> None:
        self.target_client_combo.blockSignals(True)
        self.target_client_combo.clear()
        if not bssid:
            self.target_client_combo.setEnabled(False)
            self.target_client_combo.blockSignals(False)
            return
        clients = sorted(self.clients_map.get(bssid, set()))
        if not clients:
            self.target_client_combo.setEnabled(False)
        else:
            self.target_client_combo.addItem("Все клиенты", None)
            for client in clients:
                self.target_client_combo.addItem(client, client)
            self.target_client_combo.setEnabled(True)
        self.target_client_combo.blockSignals(False)

    def _on_target_ap_changed(self) -> None:
        self._populate_clients_for_ap(self.target_ap_combo.currentData())

    def _populate_interfaces(self, interfaces: List[str]) -> None:
        current = self.interface_combo.currentText().strip()
        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        if interfaces:
            self.interface_combo.addItems(interfaces)
        if current:
            idx = self.interface_combo.findText(current)
            if idx >= 0:
                self.interface_combo.setCurrentIndex(idx)
            else:
                self.interface_combo.setEditText(current)
        elif interfaces:
            self.interface_combo.setCurrentIndex(0)
        self.interface_combo.blockSignals(False)

    def _on_refresh_interfaces(self) -> None:
        try:
            interfaces = self.controller.refresh_interfaces()
            if not interfaces:
                self.status_bar.showMessage("Беспроводные интерфейсы не найдены", 5000)
        except Exception as exc:
            self._show_error(str(exc))

    def _on_start_deauth(self) -> None:
        bssid = self.target_ap_combo.currentData()
        if not bssid:
            self._show_error("Выберите точку доступа с активными клиентами")
            return
        clients = []
        client_value = self.target_client_combo.currentData()
        if client_value:
            clients = [client_value]
        else:
            clients = sorted(self.clients_map.get(bssid, set()))
        try:
            self.controller.start_deauth(
                bssid,
                clients,
                self.deauth_count_spin.value(),
                self.deauth_interval_spin.value(),
            )
        except Exception as exc:
            self._show_error(str(exc))

    def _on_stop_deauth(self) -> None:
        try:
            self.controller.stop_deauth()
        except Exception as exc:
            self._show_error(str(exc))

    def _on_deauth_state(self, running: bool) -> None:
        self.start_deauth_btn.setEnabled(not running)
        self.stop_deauth_btn.setEnabled(running)

    def _find_row(self, table: QTableWidget, key: str) -> Optional[int]:
        for row in range(table.rowCount()):
            header_item = table.verticalHeaderItem(row)
            if header_item and header_item.data(Qt.UserRole) == key:
                return row
        return None

    def _show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Ошибка", message)

    def closeEvent(self, event) -> None:  # type: ignore
        try:
            self.controller.stop_capture()
        finally:
            super().closeEvent(event)
