from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from PyQt5.QtCore import Qt, QSettings, QThreadPool, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from ..audit import assess, priority_rank
from ..controller import WifiMonitorController
from ..detect import find_evil_twins
from ..oui import lookup_vendor
from ..timeutil import as_utc, utcnow
from .workers import Worker

# Aware "oldest possible" sentinel so rows without a timestamp sort last.
_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)


class MainWindow(QMainWindow):
    TARGET_STALE_SECONDS = 60
    AUTO_CAPTURE_TIMEOUT_MS = 45000

    def __init__(self, controller: WifiMonitorController, db_path: Optional[Path] = None, capture_dir: Optional[Path] = None) -> None:
        super().__init__()
        self.controller = controller
        self.setWindowTitle("Wifimonitor")
        self.resize(1200, 800)
        self.setMinimumSize(960, 640)
        self.ap_records: Dict[str, dict] = {}
        self.station_records: Dict[str, dict] = {}
        self.clients_map: Dict[str, Set[str]] = defaultdict(set)
        self._pmkid_aps: Set[str] = set()
        self._reported_twins: Set[str] = set()
        self._auto_capture_bssid: Optional[str] = None
        self.db_path = db_path
        self.capture_dir = capture_dir
        # Coalesced GUI refresh: capture callbacks only mark state dirty; the
        # periodic tick redraws the tables so a busy sniffer can't flood the UI.
        self._targets_dirty = False
        self._capture_running = False
        self._filter_text = ""
        self._ap_sort_col = 7  # "Обновлено" by default
        self._ap_sort_desc = True
        self._pool = QThreadPool.globalInstance()
        self._active_workers: Set[Worker] = set()
        self._settings = QSettings("wifimonitor", "wifimonitor")
        self._setup_ui()
        self._connect_signals()
        self._populate_from_db()
        self._on_deauth_state(False)
        self._restore_settings()
        self.controller.refresh_interfaces()
        self._announce_storage()
        self._relative_timer = QTimer(self)
        self._relative_timer.setInterval(1000)
        self._relative_timer.timeout.connect(self._on_tick)
        self._relative_timer.start()
        self._auto_capture_timer = QTimer(self)
        self._auto_capture_timer.setSingleShot(True)
        self._auto_capture_timer.timeout.connect(self._on_auto_capture_timeout)

    def _setup_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout()
        self.setFont(QFont("Fira Code", 10))

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
        self.stop_capture_btn.setEnabled(False)

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

        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Поиск:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Фильтр по BSSID, ESSID или MAC")
        self.search_edit.setClearButtonEnabled(True)
        search_row.addWidget(self.search_edit)
        monitor_layout.addLayout(search_row)

        splitter = QSplitter(Qt.Vertical)

        self.ap_table = QTableWidget(0, 9)
        self.ap_table.setHorizontalHeaderLabels(["№", "BSSID", "ESSID", "Канал", "Шифрование", "Сигнал", "Клиенты", "Обновлено", "Оценка"])
        self.ap_table.horizontalHeader().setStretchLastSection(True)
        self.ap_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.ap_table.horizontalHeader().setSectionsClickable(True)
        self.ap_table.horizontalHeader().sectionClicked.connect(self._on_ap_header_clicked)
        ap_group = QGroupBox("Точки доступа")
        ap_layout = QVBoxLayout()
        ap_layout.addWidget(self.ap_table)
        ap_group.setLayout(ap_layout)
        splitter.addWidget(ap_group)

        self.st_table = QTableWidget(0, 4)
        self.st_table.setHorizontalHeaderLabels(["MAC", "BSSID", "Сигнал", "Обновлено"])
        self.st_table.horizontalHeader().setStretchLastSection(True)
        self.st_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
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
        self.auto_capture_btn = QPushButton("Авто-захват")
        self.auto_capture_btn.setToolTip("deauth клиентов → перехват handshake/PMKID → экспорт 22000")
        buttons_layout.addWidget(self.start_deauth_btn)
        buttons_layout.addWidget(self.stop_deauth_btn)
        buttons_layout.addWidget(self.auto_capture_btn)
        controls_group_layout.addLayout(buttons_layout)
        controls_group.setLayout(controls_group_layout)

        handshake_layout.addWidget(controls_group)

        handshake_group = QGroupBox("Пойманные handshakes")
        handshake_group_layout = QVBoxLayout()
        self.hs_table = QTableWidget(0, 6)
        self.hs_table.setHorizontalHeaderLabels(["BSSID", "Клиент", "Тип", "Файл", "Создан", "Качество"])
        self.hs_table.horizontalHeader().setStretchLastSection(True)
        self.hs_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        font = QFont("Fira Code", 10)
        self.ap_table.setFont(font)
        self.ap_table.horizontalHeader().setFont(font)
        self.ap_table.verticalHeader().setFont(font)
        self.st_table.setFont(font)
        self.st_table.horizontalHeader().setFont(font)
        self.st_table.verticalHeader().setFont(font)
        self.hs_table.setFont(font)
        self.hs_table.horizontalHeader().setFont(font)
        self.hs_table.verticalHeader().setFont(font)
        for table in (self.ap_table, self.st_table, self.hs_table):
            table.setSelectionBehavior(QAbstractItemView.SelectRows)
            table.setSelectionMode(QAbstractItemView.SingleSelection)
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            table.setAlternatingRowColors(True)
            table.verticalHeader().setVisible(False)
        handshake_group_layout.addWidget(self.hs_table)
        handshake_group.setLayout(handshake_group_layout)
        handshake_layout.addWidget(handshake_group)

        logs_group = QGroupBox("Логи")
        logs_group_layout = QVBoxLayout()
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Fira Code", 10))
        self.log_view.setMaximumBlockCount(1000)
        logs_group_layout.addWidget(self.log_view)
        logs_group.setLayout(logs_group_layout)
        handshake_layout.addWidget(logs_group)

        handshake_tab.setLayout(handshake_layout)
        self.tabs.addTab(handshake_tab, "Перехват")

        layout.addWidget(self.tabs)

        export_layout = QHBoxLayout()
        self.export_excel_btn = QPushButton("Экспорт Excel")
        self.export_csv_btn = QPushButton("Экспорт CSV")
        self.export_report_btn = QPushButton("Отчёт HTML")
        self.export_hashcat_btn = QPushButton("Экспорт Hashcat")
        export_layout.addWidget(self.export_excel_btn)
        export_layout.addWidget(self.export_csv_btn)
        export_layout.addWidget(self.export_report_btn)
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
        self.export_csv_btn.clicked.connect(self._on_export_csv)
        self.export_report_btn.clicked.connect(self._on_export_report)
        self.export_hashcat_btn.clicked.connect(self._on_export_hashcat)
        self.search_edit.textChanged.connect(self._on_search_changed)
        self.refresh_interfaces_btn.clicked.connect(self._on_refresh_interfaces)
        self.start_deauth_btn.clicked.connect(self._on_start_deauth)
        self.stop_deauth_btn.clicked.connect(self._on_stop_deauth)
        self.auto_capture_btn.clicked.connect(self._on_auto_capture)
        self.target_ap_combo.currentIndexChanged.connect(self._on_target_ap_changed)
        self.controller.access_point_discovered.connect(self._add_access_point)
        self.controller.station_discovered.connect(self._add_station)
        self.controller.handshake_captured.connect(self._add_handshake)
        self.controller.status_changed.connect(self.status_bar.showMessage)
        self.controller.interface_ready.connect(self._on_interface_ready)
        self.controller.interface_list_changed.connect(self._populate_interfaces)
        self.controller.deauth_state_changed.connect(self._on_deauth_state)
        self.controller.log_generated.connect(self._append_log)
        self.controller.security_alert.connect(self._on_security_alert)

    def _populate_from_db(self) -> None:
        for ap in self.controller.load_access_points():
            self._add_access_point(ap)
        for station in self.controller.load_stations():
            self._add_station(station)
        for handshake in self.controller.load_handshakes():
            self._add_handshake(handshake)
        self._rebuild_access_point_table()
        self._rebuild_station_table()
        self._refresh_targets()
        self._targets_dirty = False

    def _on_set_interface(self) -> None:
        interface = self.interface_combo.currentText().strip()
        if not interface:
            self._show_error("Укажите интерфейс")
            return
        self.controller.set_interface(interface)
        self._save_settings()
        self.status_bar.showMessage(f"Выбран интерфейс {interface}")

    def _run_async(self, fn, *, busy=None, on_success=None, on_error=None) -> None:
        """Run ``fn`` in a pool thread so the GUI stays responsive.

        ``on_success(result)`` and ``on_error()`` run back on the GUI thread.
        The worker is kept referenced until it finishes so its queued signals
        are not dropped.
        """
        if busy:
            self.status_bar.showMessage(busy)
        worker = Worker(fn)
        worker.setAutoDelete(False)
        self._active_workers.add(worker)

        def _done(result) -> None:
            self._active_workers.discard(worker)
            if on_success is not None:
                on_success(result)

        def _fail(message: str) -> None:
            self._active_workers.discard(worker)
            if on_error is not None:
                on_error()
            self._show_error(message)

        worker.signals.finished.connect(_done)
        worker.signals.failed.connect(_fail)
        self._pool.start(worker)

    def _on_enable_monitor(self) -> None:
        self.enable_monitor_btn.setEnabled(False)
        self._run_async(
            self.controller.enable_monitor_mode,
            busy="Включение мониторного режима…",
            on_success=lambda _: self.enable_monitor_btn.setEnabled(True),
            on_error=lambda: self.enable_monitor_btn.setEnabled(True),
        )

    def _on_disable_monitor(self) -> None:
        self.disable_monitor_btn.setEnabled(False)
        self._run_async(
            self.controller.disable_monitor_mode,
            busy="Выключение мониторного режима…",
            on_success=lambda _: self.disable_monitor_btn.setEnabled(True),
            on_error=lambda: self.disable_monitor_btn.setEnabled(True),
        )

    def _on_start_capture(self) -> None:
        self.start_capture_btn.setEnabled(False)

        def ok(_) -> None:
            self._capture_running = True
            self.stop_capture_btn.setEnabled(True)

        self._run_async(
            self.controller.start_capture,
            busy="Запуск захвата…",
            on_success=ok,
            on_error=lambda: self.start_capture_btn.setEnabled(True),
        )

    def _on_stop_capture(self) -> None:
        self.stop_capture_btn.setEnabled(False)

        def ok(_) -> None:
            self._capture_running = False
            self.start_capture_btn.setEnabled(True)

        self._run_async(
            self.controller.stop_capture,
            busy="Остановка захвата…",
            on_success=ok,
            on_error=lambda: self.stop_capture_btn.setEnabled(True),
        )

    def _on_export_excel(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(self, "Сохранить Excel", "results.xlsx", "Excel (*.xlsx)")
        if not destination:
            return
        self.export_excel_btn.setEnabled(False)

        def ok(_) -> None:
            self.export_excel_btn.setEnabled(True)
            self.status_bar.showMessage("Экспорт Excel выполнен", 5000)

        self._run_async(
            lambda: self.controller.export_excel(Path(destination)),
            busy="Экспорт в Excel…",
            on_success=ok,
            on_error=lambda: self.export_excel_btn.setEnabled(True),
        )

    def _on_export_csv(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(self, "Сохранить CSV", "networks.csv", "CSV (*.csv)")
        if not destination:
            return
        self.export_csv_btn.setEnabled(False)

        def ok(clients_path) -> None:
            self.export_csv_btn.setEnabled(True)
            self.status_bar.showMessage(f"CSV сохранён (клиенты: {Path(clients_path).name})", 5000)

        self._run_async(
            lambda: self.controller.export_csv(Path(destination)),
            busy="Экспорт в CSV…",
            on_success=ok,
            on_error=lambda: self.export_csv_btn.setEnabled(True),
        )

    def _on_export_report(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", "report.html", "HTML (*.html)")
        if not destination:
            return
        self.export_report_btn.setEnabled(False)

        def ok(_) -> None:
            self.export_report_btn.setEnabled(True)
            self.status_bar.showMessage("Отчёт HTML сохранён", 5000)

        self._run_async(
            lambda: self.controller.export_report(Path(destination)),
            busy="Формирование отчёта…",
            on_success=ok,
            on_error=lambda: self.export_report_btn.setEnabled(True),
        )

    def _on_export_hashcat(self) -> None:
        row = self.hs_table.currentRow()
        if row < 0:
            self._show_error("Выберите handshake")
            return
        capture_path_item = self.hs_table.item(row, 3)
        if not capture_path_item:
            self._show_error("Не найден путь к файлу")
            return
        capture_path = Path(capture_path_item.text())
        destination, _ = QFileDialog.getSaveFileName(self, "Сохранить Hashcat", f"{capture_path.stem}.hc22000", "Hashcat (*.hc22000)")
        if not destination:
            return
        self.export_hashcat_btn.setEnabled(False)

        def ok(_) -> None:
            self.export_hashcat_btn.setEnabled(True)
            self.status_bar.showMessage("Экспорт Hashcat выполнен", 5000)

        self._run_async(
            lambda: self.controller.export_hashcat(capture_path, Path(destination)),
            busy="Экспорт в Hashcat…",
            on_success=ok,
            on_error=lambda: self.export_hashcat_btn.setEnabled(True),
        )

    def _add_access_point(self, ap: dict) -> None:
        ap = dict(ap)
        bssid = ap["bssid"]
        previous = self.ap_records.get(bssid, {})
        last_seen_dt = self._parse_timestamp(ap.get("last_seen"))
        previous_dt = previous.get("last_seen_dt")
        if last_seen_dt and previous_dt and last_seen_dt < previous_dt:
            last_seen_dt = previous_dt
        if not last_seen_dt:
            last_seen_dt = previous_dt
        if last_seen_dt:
            ap["last_seen_dt"] = last_seen_dt
        self.ap_records[bssid] = {**previous, **ap}
        self._targets_dirty = True

    def _add_station(self, station: dict) -> None:
        station = dict(station)
        bssid = station.get("associated_bssid")
        mac = station.get("mac")
        if not mac:
            return
        previous = self.station_records.get(mac, {})
        last_seen_dt = self._parse_timestamp(station.get("last_seen"))
        previous_dt = previous.get("last_seen_dt")
        if last_seen_dt and previous_dt and last_seen_dt < previous_dt:
            last_seen_dt = previous_dt
        if not last_seen_dt:
            last_seen_dt = previous_dt
        if last_seen_dt:
            station["last_seen_dt"] = last_seen_dt
        self.station_records[mac] = {**previous, **station}
        if bssid:
            self.clients_map[bssid].add(mac)
        self._targets_dirty = True

    def _add_handshake(self, handshake: dict) -> None:
        kind = handshake.get("kind") or "handshake"
        if kind == "pmkid" and handshake.get("bssid"):
            self._pmkid_aps.add(handshake["bssid"])
        key = f"{handshake.get('bssid')}->{handshake.get('station_mac')}:{kind}"
        self._update_row(self.hs_table, key, [
            self._to_text(handshake.get("bssid")),
            self._to_text(handshake.get("station_mac")),
            self._to_text(kind),
            self._to_text(handshake.get("capture_path")),
            self._to_text(handshake.get("created_at")),
            self._to_text(handshake.get("quality")),
        ])
        self._auto_resize_table(self.hs_table)
        if self._auto_capture_bssid and handshake.get("bssid") == self._auto_capture_bssid:
            self._finish_auto_capture(handshake)

    def _append_log(self, message: str) -> None:
        if not hasattr(self, "log_view"):
            return
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _announce_storage(self) -> None:
        parts = []
        if self.db_path:
            parts.append(f"БД: {self.db_path}")
        if self.capture_dir:
            parts.append(f"Захваты: {self.capture_dir}")
        if not parts:
            return
        message = " | ".join(parts)
        self.status_bar.showMessage(message, 10000)
        self._append_log(f"Используется {message}")

    def _update_row(self, table: QTableWidget, key: str, values: List[str], prepend_index: bool = False) -> None:
        row = self._find_row(table, key)
        if row is None:
            row = table.rowCount()
            table.insertRow(row)
            key_item = QTableWidgetItem(key)
            key_item.setData(Qt.UserRole, key)
            table.setVerticalHeaderItem(row, key_item)
        if prepend_index:
            number_item = QTableWidgetItem(str(row + 1))
            number_item.setTextAlignment(Qt.AlignCenter)
            table.setItem(row, 0, number_item)
            start_col = 1
        else:
            start_col = 0
        for col, value in enumerate(values):
            item = QTableWidgetItem(value or "")
            table.setItem(row, start_col + col, item)

    def _to_text(self, value) -> str:
        if value is None:
            return ""
        return str(value)

    def _current_row_key(self, table: QTableWidget) -> Optional[str]:
        row = table.currentRow()
        if row < 0:
            return None
        header = table.verticalHeaderItem(row)
        return header.data(Qt.UserRole) if header else None

    def _restore_row_key(self, table: QTableWidget, key: Optional[str]) -> None:
        if not key:
            return
        row = self._find_row(table, key)
        if row is not None:
            table.setCurrentCell(row, 0)

    def _ap_sort_key(self, item):
        bssid, ap = item
        col = self._ap_sort_col
        if col == 1:
            return (ap.get("bssid") or "").lower()
        if col == 2:
            return (ap.get("essid") or "").lower()
        if col == 3:
            return ap.get("channel") or 0
        if col == 4:
            return (ap.get("encryption") or "").lower()
        if col == 5:
            signal = ap.get("signal")
            return signal if signal is not None else -9999
        if col == 6:
            return len(self._active_clients_for_ap(bssid))
        if col == 8:
            label, _ = assess(
                ap.get("encryption"),
                wps=bool(ap.get("wps")),
                mfp_required=bool(ap.get("mfp_required")),
                signal=ap.get("signal"),
                client_count=len(self._active_clients_for_ap(bssid)),
                has_pmkid=bssid in self._pmkid_aps,
            )
            return priority_rank(label)
        return ap.get("last_seen_dt") or _MIN_DT

    def _on_ap_header_clicked(self, col: int) -> None:
        if col == 0:  # the row-number column is not a sort key
            return
        if col == self._ap_sort_col:
            self._ap_sort_desc = not self._ap_sort_desc
        else:
            self._ap_sort_col = col
            self._ap_sort_desc = col in (5, 6, 7, 8)  # signal/clients/last-seen/verdict default to desc
        self._rebuild_access_point_table()

    def _rebuild_access_point_table(self) -> None:
        key = self._current_row_key(self.ap_table)
        self.ap_table.setUpdatesEnabled(False)
        rows = sorted(self.ap_records.items(), key=self._ap_sort_key, reverse=self._ap_sort_desc)
        self.ap_table.setRowCount(len(rows))
        for row_idx, (bssid, ap) in enumerate(rows):
            self._set_access_point_row(row_idx, bssid, ap)
        self._auto_resize_table(self.ap_table)
        self._apply_filter(self.ap_table)
        self.ap_table.setUpdatesEnabled(True)
        self._restore_row_key(self.ap_table, key)

    def _rebuild_station_table(self) -> None:
        key = self._current_row_key(self.st_table)
        self.st_table.setUpdatesEnabled(False)
        rows = sorted(
            self.station_records.items(),
            key=lambda item: item[1].get("last_seen_dt") or _MIN_DT,
            reverse=True,
        )
        self.st_table.setRowCount(len(rows))
        for row_idx, (mac, station) in enumerate(rows):
            self._set_station_row(row_idx, mac, station)
        self._auto_resize_table(self.st_table)
        self._apply_filter(self.st_table)
        self.st_table.setUpdatesEnabled(True)
        self._restore_row_key(self.st_table, key)

    def _on_search_changed(self, text: str) -> None:
        self._filter_text = text.strip().lower()
        self._apply_filter(self.ap_table)
        self._apply_filter(self.st_table)

    def _apply_filter(self, table: QTableWidget) -> None:
        text = self._filter_text
        for row in range(table.rowCount()):
            if not text:
                table.setRowHidden(row, False)
                continue
            match = False
            for col in range(table.columnCount()):
                item = table.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            table.setRowHidden(row, not match)

    def _set_access_point_row(self, row_idx: int, bssid: str, ap: dict) -> None:
        key_item = QTableWidgetItem(bssid)
        key_item.setData(Qt.UserRole, bssid)
        key_item.setFlags(key_item.flags() & ~Qt.ItemIsEditable)
        self.ap_table.setVerticalHeaderItem(row_idx, key_item)

        number_item = QTableWidgetItem(str(row_idx + 1))
        number_item.setTextAlignment(Qt.AlignCenter)
        number_item.setFlags(number_item.flags() & ~Qt.ItemIsEditable)
        self.ap_table.setItem(row_idx, 0, number_item)

        bssid_item = QTableWidgetItem(self._to_text(ap.get("bssid")))
        bssid_item.setFlags(bssid_item.flags() & ~Qt.ItemIsEditable)
        vendor = lookup_vendor(bssid)
        if vendor:
            bssid_item.setToolTip(f"Производитель: {vendor}")
        self.ap_table.setItem(row_idx, 1, bssid_item)

        essid_item = QTableWidgetItem(self._to_text(ap.get("essid")))
        essid_item.setFlags(essid_item.flags() & ~Qt.ItemIsEditable)
        self.ap_table.setItem(row_idx, 2, essid_item)

        channel_item = QTableWidgetItem(self._to_text(ap.get("channel")))
        channel_item.setTextAlignment(Qt.AlignCenter)
        channel_item.setFlags(channel_item.flags() & ~Qt.ItemIsEditable)
        self.ap_table.setItem(row_idx, 3, channel_item)

        encryption_item = QTableWidgetItem(self._to_text(ap.get("encryption")))
        encryption_item.setFlags(encryption_item.flags() & ~Qt.ItemIsEditable)
        self.ap_table.setItem(row_idx, 4, encryption_item)

        signal_item = QTableWidgetItem(self._to_text(ap.get("signal")))
        signal_item.setTextAlignment(Qt.AlignCenter)
        signal_item.setFlags(signal_item.flags() & ~Qt.ItemIsEditable)
        self.ap_table.setItem(row_idx, 5, signal_item)

        active_clients = len(self._active_clients_for_ap(bssid))
        clients_item = QTableWidgetItem(self._to_text(active_clients))
        clients_item.setTextAlignment(Qt.AlignCenter)
        clients_item.setFlags(clients_item.flags() & ~Qt.ItemIsEditable)
        self.ap_table.setItem(row_idx, 6, clients_item)

        last_seen_dt = ap.get("last_seen_dt")
        last_seen_item = QTableWidgetItem(self._format_time_since(last_seen_dt))
        last_seen_item.setFlags(last_seen_item.flags() & ~Qt.ItemIsEditable)
        last_seen_item.setData(Qt.UserRole, last_seen_dt.timestamp() if last_seen_dt else float("-inf"))
        self.ap_table.setItem(row_idx, 7, last_seen_item)

        label, detail = assess(
            ap.get("encryption"),
            wps=bool(ap.get("wps")),
            mfp_required=bool(ap.get("mfp_required")),
            signal=ap.get("signal"),
            client_count=active_clients,
            has_pmkid=bssid in self._pmkid_aps,
        )
        verdict_item = QTableWidgetItem(label)
        verdict_item.setFlags(verdict_item.flags() & ~Qt.ItemIsEditable)
        verdict_item.setToolTip(detail)
        verdict_item.setData(Qt.UserRole, priority_rank(label))
        self.ap_table.setItem(row_idx, 8, verdict_item)

    def _set_station_row(self, row_idx: int, mac: str, station: dict) -> None:
        key_item = QTableWidgetItem(mac)
        key_item.setData(Qt.UserRole, mac)
        key_item.setFlags(key_item.flags() & ~Qt.ItemIsEditable)
        self.st_table.setVerticalHeaderItem(row_idx, key_item)

        mac_item = QTableWidgetItem(self._to_text(station.get("mac")))
        mac_item.setFlags(mac_item.flags() & ~Qt.ItemIsEditable)
        self.st_table.setItem(row_idx, 0, mac_item)

        bssid_item = QTableWidgetItem(self._to_text(station.get("associated_bssid")))
        bssid_item.setFlags(bssid_item.flags() & ~Qt.ItemIsEditable)
        self.st_table.setItem(row_idx, 1, bssid_item)

        signal_item = QTableWidgetItem(self._to_text(station.get("signal")))
        signal_item.setTextAlignment(Qt.AlignCenter)
        signal_item.setFlags(signal_item.flags() & ~Qt.ItemIsEditable)
        self.st_table.setItem(row_idx, 2, signal_item)

        last_seen_dt = station.get("last_seen_dt")
        last_seen_item = QTableWidgetItem(self._format_time_since(last_seen_dt))
        last_seen_item.setFlags(last_seen_item.flags() & ~Qt.ItemIsEditable)
        last_seen_item.setData(Qt.UserRole, last_seen_dt.timestamp() if last_seen_dt else float("-inf"))
        self.st_table.setItem(row_idx, 3, last_seen_item)

    def _on_tick(self) -> None:
        # Runs once per second: redraw tables so relative "last seen" values
        # keep counting, and refresh the deauth target combos only when new
        # access points or clients arrived since the previous tick.
        self._rebuild_access_point_table()
        self._rebuild_station_table()
        if self._targets_dirty:
            self._refresh_targets()
            self._targets_dirty = False
        self._check_evil_twins()

    def _on_security_alert(self, message: str) -> None:
        self.status_bar.showMessage(f"⚠ {message}", 10000)

    def _check_evil_twins(self) -> None:
        twins = find_evil_twins(self.ap_records.values())
        for essid, bssids in twins.items():
            if essid not in self._reported_twins:
                self._reported_twins.add(essid)
                self._append_log(
                    f"[ВНИМАНИЕ] Возможный evil-twin: ESSID «{essid}» на {len(bssids)} BSSID"
                )

    def _auto_resize_table(self, table: QTableWidget) -> None:
        if table.columnCount() == 0:
            return
        table.resizeColumnsToContents()

    def _is_recent(self, last_seen: Optional[datetime], threshold: Optional[int] = None) -> bool:
        if not last_seen:
            return False
        limit = threshold if threshold is not None else self.TARGET_STALE_SECONDS
        return (utcnow() - last_seen) <= timedelta(seconds=limit)

    def _active_clients_for_ap(self, bssid: str) -> List[str]:
        clients = self.clients_map.get(bssid, set())
        active: List[str] = []
        for mac in clients:
            station = self.station_records.get(mac)
            if not station:
                continue
            if self._is_recent(station.get("last_seen_dt")):
                active.append(mac)
        return active

    def _format_time_since(self, last_seen: Optional[datetime]) -> str:
        if not last_seen:
            return ""
        now = utcnow()
        delta = now - last_seen
        seconds = int(max(delta.total_seconds(), 0))
        if seconds < 1:
            return "только что"
        if seconds < 60:
            return f"{seconds} сек назад"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes} мин назад"
        hours = minutes // 60
        if hours < 24:
            return f"{hours} ч назад"
        days = hours // 24
        return f"{days} дн назад"

    def _parse_timestamp(self, value) -> Optional[datetime]:
        if isinstance(value, datetime):
            return as_utc(value)
        if isinstance(value, str) and value:
            try:
                return as_utc(datetime.fromisoformat(value))
            except ValueError:
                return None
        return None

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
        current_client: Optional[str] = None
        select_all = False
        if self.target_client_combo.count() > 0:
            current_client = self.target_client_combo.currentData()
            select_all = self.target_client_combo.currentIndex() == 0 and current_client is None
        self.target_ap_combo.blockSignals(True)
        self.target_ap_combo.clear()
        for bssid, ap in sorted(self.ap_records.items()):
            if not self._is_recent(ap.get("last_seen_dt")):
                continue
            clients = sorted(self._active_clients_for_ap(bssid))
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
        selected_bssid = self.target_ap_combo.currentData()
        if selected_bssid == current_bssid:
            self._populate_clients_for_ap(selected_bssid, current_client, select_all)
        else:
            self._populate_clients_for_ap(selected_bssid)

    def _populate_clients_for_ap(self, bssid: Optional[str], selected_client: Optional[str] = None, select_all: bool = False) -> None:
        self.target_client_combo.blockSignals(True)
        self.target_client_combo.clear()
        if not bssid:
            self.target_client_combo.setEnabled(False)
            self.target_client_combo.blockSignals(False)
            return
        clients = sorted(self._active_clients_for_ap(bssid))
        if not clients:
            self.target_client_combo.setEnabled(False)
        else:
            self.target_client_combo.addItem("Все клиенты", None)
            for client in clients:
                self.target_client_combo.addItem(client, client)
            if select_all:
                self.target_client_combo.setCurrentIndex(0)
            elif selected_client:
                idx = self.target_client_combo.findData(selected_client)
                if idx >= 0:
                    self.target_client_combo.setCurrentIndex(idx)
                else:
                    self.target_client_combo.setCurrentIndex(0)
            else:
                self.target_client_combo.setCurrentIndex(0)
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
        self.refresh_interfaces_btn.setEnabled(False)

        def ok(interfaces) -> None:
            self.refresh_interfaces_btn.setEnabled(True)
            if not interfaces:
                self.status_bar.showMessage("Беспроводные интерфейсы не найдены", 5000)

        self._run_async(
            self.controller.refresh_interfaces,
            busy="Обновление списка интерфейсов…",
            on_success=ok,
            on_error=lambda: self.refresh_interfaces_btn.setEnabled(True),
        )

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
            clients = sorted(self._active_clients_for_ap(bssid))
        if not clients:
            self._show_error("Активные клиенты не найдены")
            return
        essid = self.ap_records.get(bssid, {}).get("essid") or bssid
        target = clients[0] if len(clients) == 1 else f"всех активных клиентов ({len(clients)})"
        reply = QMessageBox.question(
            self,
            "Подтверждение деаутентификации",
            f"Отправить deauth-кадры для {target} на сети «{essid}»?\n\n"
            "Убедитесь, что у вас есть разрешение на тестирование этой сети.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._save_settings()
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
        self._auto_capture_bssid = None
        self._auto_capture_timer.stop()
        try:
            self.controller.stop_deauth()
        except Exception as exc:
            self._show_error(str(exc))

    def _on_auto_capture(self) -> None:
        bssid = self.target_ap_combo.currentData()
        if not bssid:
            self._show_error("Выберите точку доступа с активными клиентами")
            return
        client_value = self.target_client_combo.currentData()
        clients = [client_value] if client_value else sorted(self._active_clients_for_ap(bssid))
        if not clients:
            self._show_error("Активные клиенты не найдены")
            return
        essid = self.ap_records.get(bssid, {}).get("essid") or bssid
        reply = QMessageBox.question(
            self,
            "Авто-захват",
            f"Запустить авто-захват для сети «{essid}»?\n\n"
            "Будет выполнена деаутентификация клиентов для получения handshake/PMKID, "
            "после чего первый захват автоматически экспортируется в hashcat 22000.\n"
            "Убедитесь, что у вас есть разрешение на тестирование этой сети.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._save_settings()
        try:
            self.controller.start_deauth(
                bssid,
                clients,
                self.deauth_count_spin.value(),
                self.deauth_interval_spin.value(),
            )
        except Exception as exc:
            self._show_error(str(exc))
            return
        self._auto_capture_bssid = bssid
        self._auto_capture_timer.start(self.AUTO_CAPTURE_TIMEOUT_MS)
        self.status_bar.showMessage(f"Авто-захват запущен для {essid}", 5000)

    def _finish_auto_capture(self, handshake: dict) -> None:
        self._auto_capture_timer.stop()
        bssid = self._auto_capture_bssid
        self._auto_capture_bssid = None
        try:
            self.controller.stop_deauth()
        except Exception:  # noqa: BLE001 - already stopping, ignore
            pass
        kind = handshake.get("kind") or "handshake"
        capture_path = handshake.get("capture_path")
        if not capture_path or not self.capture_dir:
            self.status_bar.showMessage(f"Авто-захват: получен {kind}", 8000)
            return
        out = Path(self.capture_dir) / f"{str(bssid or '').replace(':', '')}_{kind}.hc22000"

        def ok(_) -> None:
            self.status_bar.showMessage(f"Авто-захват: {kind} → {out.name}", 8000)

        self._run_async(
            lambda: self.controller.export_hashcat(Path(capture_path), out),
            busy=f"Авто-захват: экспорт {kind}…",
            on_success=ok,
            on_error=lambda: self.status_bar.showMessage(
                f"Авто-захват: {kind} получен, экспорт не удался", 8000
            ),
        )

    def _on_auto_capture_timeout(self) -> None:
        if not self._auto_capture_bssid:
            return
        self._auto_capture_bssid = None
        try:
            self.controller.stop_deauth()
        except Exception:  # noqa: BLE001
            pass
        self.status_bar.showMessage("Авто-захват: handshake не пойман, остановлено", 8000)

    def _on_deauth_state(self, running: bool) -> None:
        self.start_deauth_btn.setEnabled(not running)
        self.stop_deauth_btn.setEnabled(running)
        self.auto_capture_btn.setEnabled(not running)

    def _find_row(self, table: QTableWidget, key: str) -> Optional[int]:
        for row in range(table.rowCount()):
            header_item = table.verticalHeaderItem(row)
            if header_item and header_item.data(Qt.UserRole) == key:
                return row
        return None

    def _show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Ошибка", message)

    def _restore_settings(self) -> None:
        iface = self._settings.value("interface", "", type=str)
        if iface:
            self.interface_combo.setEditText(iface)
        self.deauth_count_spin.setValue(
            self._settings.value("deauth/count", self.deauth_count_spin.value(), type=int)
        )
        self.deauth_interval_spin.setValue(
            self._settings.value("deauth/interval", self.deauth_interval_spin.value(), type=float)
        )

    def _save_settings(self) -> None:
        self._settings.setValue("interface", self.interface_combo.currentText().strip())
        self._settings.setValue("deauth/count", self.deauth_count_spin.value())
        self._settings.setValue("deauth/interval", self.deauth_interval_spin.value())

    def closeEvent(self, event) -> None:  # type: ignore
        try:
            self._save_settings()
            self.controller.stop_capture()
        finally:
            super().closeEvent(event)
