"""A small dependency-free RSSI-over-time plot for the locator/hunt view.

Drawn with QPainter so no external plotting library is needed. The main window
feeds it a list of ``(timestamp, rssi_dbm)`` samples for the selected target.
"""

from __future__ import annotations

from typing import List, Tuple

from PyQt5.QtCore import QPointF, Qt
from PyQt5.QtGui import QColor, QPainter, QPen
from PyQt5.QtWidgets import QWidget

_RSSI_MIN = -100
_RSSI_MAX = -20


class RssiPlot(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._points: List[Tuple[float, int]] = []
        self.setMinimumHeight(200)

    def set_series(self, points) -> None:
        self._points = list(points)
        self.update()

    def _y(self, dbm: float, height: int) -> float:
        dbm = max(_RSSI_MIN, min(_RSSI_MAX, dbm))
        return height - (dbm - _RSSI_MIN) / (_RSSI_MAX - _RSSI_MIN) * height

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width = self.width()
        height = self.height()
        painter.fillRect(0, 0, width, height, QColor("#050810"))

        grid = QPen(QColor("#1f3552"))
        painter.setPen(grid)
        for dbm in range(_RSSI_MIN, _RSSI_MAX + 1, 20):
            y = int(self._y(dbm, height))
            painter.drawLine(0, y, width, y)
            painter.drawText(2, max(10, y - 2), f"{dbm} dBm")

        points = self._points
        if len(points) < 2:
            return
        t0 = points[0][0]
        span = max(points[-1][0] - t0, 1e-3)
        line = QPen(QColor("#3fffaf"))
        line.setWidth(2)
        painter.setPen(line)
        previous = None
        for timestamp, rssi in points:
            x = (timestamp - t0) / span * (width - 1)
            current = QPointF(x, self._y(rssi, height))
            if previous is not None:
                painter.drawLine(previous, current)
            previous = current
