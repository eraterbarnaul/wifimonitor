"""Small time helpers so the whole app uses timezone-aware UTC consistently."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC ``datetime``."""
    return datetime.now(timezone.utc)


def as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Normalise a ``datetime`` to timezone-aware UTC.

    Naive values (e.g. read from databases written by older versions that
    stored ``datetime.utcnow()``) are assumed to already be in UTC. Aware
    values are converted. ``None`` passes through unchanged.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
