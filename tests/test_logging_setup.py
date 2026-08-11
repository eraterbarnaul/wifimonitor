"""Tests for the rotating file logging setup."""

import logging

import pytest

from wifimonitor.logging_setup import LOGGER_NAME, configure_logging


@pytest.fixture(autouse=True)
def _reset_wifimonitor_logger():
    """configure_logging() attaches a handler to the process-global logger;

    strip it back off so this test file doesn't leak file handles/state into
    whatever else in the suite happens to log through "wifimonitor".
    """
    yield
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        if getattr(handler, "_wifimonitor", False):
            logger.removeHandler(handler)
            handler.close()


def test_configure_logging_creates_log_file(tmp_path):
    log_path = configure_logging(tmp_path)
    assert log_path == tmp_path / "wifimonitor.log"
    logger = logging.getLogger(LOGGER_NAME)
    logger.info("hello")
    for handler in logger.handlers:
        handler.flush()
    assert log_path.exists()
    assert "hello" in log_path.read_text(encoding="utf-8")


def test_configure_logging_is_idempotent(tmp_path):
    configure_logging(tmp_path)
    logger = logging.getLogger(LOGGER_NAME)
    handler_count_before = len(logger.handlers)
    configure_logging(tmp_path)
    assert len(logger.handlers) == handler_count_before
