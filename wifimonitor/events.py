"""Event bus for decoupling components from Qt signals.

Provides a simple publish/subscribe mechanism that can be used by any layer
(CLI, GUI, REST API) without requiring PyQt5. The Qt controller adapter
bridges events to pyqtSignals for the UI.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional


class EventBus:
    """Thread-safe publish/subscribe event bus."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable[..., Any]]] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, event: str, callback: Callable[..., Any]) -> None:
        with self._lock:
            self._subscribers[event].append(callback)

    def unsubscribe(self, event: str, callback: Callable[..., Any]) -> None:
        with self._lock:
            try:
                self._subscribers[event].remove(callback)
            except ValueError:
                pass

    def emit(self, event: str, *args: Any, **kwargs: Any) -> None:
        with self._lock:
            callbacks = list(self._subscribers.get(event, []))
        for cb in callbacks:
            try:
                cb(*args, **kwargs)
            except Exception:  # noqa: BLE001
                pass

    def clear(self) -> None:
        with self._lock:
            self._subscribers.clear()


# Canonical event names used throughout the application.
class Events:
    ACCESS_POINT_DISCOVERED = "access_point_discovered"
    STATION_DISCOVERED = "station_discovered"
    HANDSHAKE_CAPTURED = "handshake_captured"
    STATUS_CHANGED = "status_changed"
    INTERFACE_READY = "interface_ready"
    INTERFACE_LIST_CHANGED = "interface_list_changed"
    DEAUTH_STATE_CHANGED = "deauth_state_changed"
    LOG_GENERATED = "log_generated"
    SECURITY_ALERT = "security_alert"
    PROBE_DISCOVERED = "probe_discovered"
    WPS_STATE_CHANGED = "wps_state_changed"
    WPS_CRACKED = "wps_cracked"
    CRACK_STATE_CHANGED = "crack_state_changed"
    CRACK_CRACKED = "crack_cracked"
    EVIL_TWIN_DETECTED = "evil_twin_detected"
    AUTO_ATTACK_PROGRESS = "auto_attack_progress"
    AUTO_ATTACK_COMPLETE = "auto_attack_complete"
