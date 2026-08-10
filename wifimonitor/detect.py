"""Passive blue-team heuristics: deauth floods, evil twins, rogue APs.

Pure and dependency-free so the detection logic can be unit tested with
injected timestamps and access-point dicts. The capture layer feeds frame
timestamps in, and the controller/UI surface the alerts.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Set, Tuple


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


class EvilTwinDetector:
    """Real-time evil twin detector.

    Tracks ESSID → set of BSSIDs. When a new BSSID appears for an already-known
    ESSID, an alert is generated. Also detects channel/encryption changes for
    existing APs which may indicate an evil twin attempting to mimic the original.
    """

    def __init__(self, cooldown: float = 60.0) -> None:
        self._by_essid: Dict[str, Set[str]] = defaultdict(set)
        self._ap_info: Dict[str, dict] = {}  # bssid -> {essid, channel, encryption}
        self._alerted: Set[Tuple[str, str]] = set()  # (essid, bssid) pairs already alerted
        self.cooldown = cooldown
        self._last_alerts: Dict[str, float] = {}  # essid -> last alert timestamp

    def check(self, bssid: str, essid: Optional[str], channel: Optional[int] = None,
              encryption: Optional[str] = None, timestamp: float = 0.0) -> Optional[str]:
        """Check a newly seen AP for evil twin indicators. Returns an alert or None."""
        if not essid or not bssid:
            return None

        existing_bssids = set(self._by_essid[essid])  # snapshot before adding
        self._by_essid[essid].add(bssid)

        # Store AP info for change detection
        prev_info = self._ap_info.get(bssid)
        self._ap_info[bssid] = {"essid": essid, "channel": channel, "encryption": encryption}

        # Check for encryption/channel change on existing AP (possible takeover)
        if prev_info and prev_info["essid"] == essid:
            changes = []
            if prev_info.get("encryption") and encryption and prev_info["encryption"] != encryption:
                changes.append(f"шифрование: {prev_info['encryption']} → {encryption}")
            if prev_info.get("channel") and channel and prev_info["channel"] != channel:
                changes.append(f"канал: {prev_info['channel']} → {channel}")
            if changes:
                key = (essid, bssid)
                last = self._last_alerts.get(essid, 0.0)
                if key not in self._alerted or (timestamp - last > self.cooldown):
                    self._alerted.add(key)
                    self._last_alerts[essid] = timestamp
                    return f"Подозрительное изменение {essid} ({bssid}): {'; '.join(changes)}"

        # Check for multiple BSSIDs on one ESSID (new BSSID appearing)
        if len(existing_bssids) > 0 and bssid not in existing_bssids:
            # This BSSID is new for this ESSID
            last = self._last_alerts.get(essid)
            if last is None or (timestamp - last > self.cooldown):
                self._alerted.add((essid, bssid))
                self._last_alerts[essid] = timestamp
                count = len(self._by_essid[essid])
                return (
                    f"Возможный Evil Twin: ESSID «{essid}» обнаружен на {count} BSSID "
                    f"(новый: {bssid})"
                )

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
