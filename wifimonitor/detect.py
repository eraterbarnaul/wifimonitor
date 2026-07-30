"""Passive blue-team heuristics: deauth floods and evil twins.

Pure and dependency-free so the detection logic can be unit tested with
injected timestamps and access-point dicts. The capture layer feeds frame
timestamps in, and the controller/UI surface the alerts.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional


class DeauthFloodDetector:
    """Sliding-window detector for bursts of deauth/disassoc frames."""

    def __init__(self, window: float = 5.0, threshold: int = 30, cooldown: float = 15.0) -> None:
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown
        self._events: deque = deque()
        self._last_alert = float("-inf")

    def add(self, timestamp: float) -> Optional[str]:
        """Record one deauth/disassoc frame; return an alert string if flooding."""
        self._events.append(timestamp)
        cutoff = timestamp - self.window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        if len(self._events) >= self.threshold and timestamp - self._last_alert >= self.cooldown:
            self._last_alert = timestamp
            return f"deauth-флуд: {len(self._events)} кадров за {self.window:.0f} с"
        return None


def find_evil_twins(access_points: Iterable[dict]) -> Dict[str, List[str]]:
    """Return ESSIDs advertised by more than one BSSID (possible evil twins).

    Legitimate multi-AP/roaming networks also share an ESSID, so this is an
    advisory signal, not proof.
    """
    by_essid: Dict[str, set] = defaultdict(set)
    for ap in access_points:
        essid = ap.get("essid")
        bssid = ap.get("bssid")
        if essid and bssid:
            by_essid[essid].add(bssid)
    return {essid: sorted(bssids) for essid, bssids in by_essid.items() if len(bssids) > 1}
