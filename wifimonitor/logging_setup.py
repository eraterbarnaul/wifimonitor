"""Rotating file logging for the application.

The controller mirrors every user-facing log line into the ``wifimonitor``
logger, so configuring this once at startup gives a persistent on-disk record
in ``~/.wifimonitor/wifimonitor.log`` in addition to the in-app log view.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER_NAME = "wifimonitor"


def configure_logging(log_dir: Path, level: int = logging.INFO) -> Path:
    """Attach a rotating file handler to the ``wifimonitor`` logger (idempotent)."""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "wifimonitor.log"

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    already = any(getattr(h, "_wifimonitor", False) for h in logger.handlers)
    if not already:
        handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler._wifimonitor = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return log_path
