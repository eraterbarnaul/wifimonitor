"""GUI smoke test: MainWindow must construct and tear down cleanly.

Needs a real (if headless) Qt platform plugin, so CI sets QT_QPA_PLATFORM=offscreen
for the test job. This isn't behavioral coverage of the 1500-line window class — just
a guard against import-time/constructor crashes (missing widgets, bad enum references,
etc.) that unit tests mocking the controller can't catch.
"""

import pytest

pytest.importorskip("PyQt5")

from PyQt5.QtWidgets import QApplication  # noqa: E402

from wifimonitor.controller import WifiMonitorController  # noqa: E402
from wifimonitor.ui.main_window import MainWindow  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_constructs_and_closes(qapp, tmp_path):
    db_path = tmp_path / "smoke.db"
    capture_dir = tmp_path / "captures"
    capture_dir.mkdir()

    controller = WifiMonitorController(db_path=db_path, capture_dir=capture_dir)
    window = MainWindow(controller, db_path=db_path, capture_dir=capture_dir)
    try:
        window.show()
        qapp.processEvents()
        assert window.tabs.count() > 0
        tab_labels = [window.tabs.tabText(i) for i in range(window.tabs.count())]
        assert len(tab_labels) == len(set(tab_labels))  # no duplicate tabs
    finally:
        window.close()
        qapp.processEvents()
