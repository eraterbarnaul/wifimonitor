"""Tests for the UTC time helpers used throughout storage/display."""

from datetime import datetime, timedelta, timezone

from wifimonitor.timeutil import as_utc, utcnow


def test_utcnow_is_aware_and_utc():
    now = utcnow()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_as_utc_none_passes_through():
    assert as_utc(None) is None


def test_as_utc_naive_value_assumed_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    result = as_utc(naive)
    assert result.tzinfo == timezone.utc
    assert result.hour == 12  # naive value kept as-is, just tagged UTC


def test_as_utc_aware_value_converted():
    moscow = timezone(timedelta(hours=3))
    aware = datetime(2026, 1, 1, 15, 0, 0, tzinfo=moscow)
    result = as_utc(aware)
    assert result.tzinfo == timezone.utc
    assert result.hour == 12  # 15:00 MSK == 12:00 UTC
