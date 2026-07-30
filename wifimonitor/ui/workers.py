"""Helpers for running blocking work off the Qt GUI thread.

Operations such as ``airmon-ng start`` or a Hashcat export shell out to
external tools and can block for several seconds. Running them directly in a
slot freezes the whole interface, so they are dispatched to a ``QThreadPool``
via :class:`Worker` and report back through queued signals.
"""

from __future__ import annotations

from typing import Any, Callable

from PyQt5.QtCore import QObject, QRunnable, pyqtSignal, pyqtSlot


class WorkerSignals(QObject):
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)


class Worker(QRunnable):
    """Run ``fn(*args, **kwargs)`` in a pool thread and emit the outcome."""

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as exc:  # noqa: BLE001 - report every failure to the UI
            self.signals.failed.emit(str(exc))
        else:
            self.signals.finished.emit(result)
