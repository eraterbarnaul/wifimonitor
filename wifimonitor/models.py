from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .timeutil import utcnow


@dataclass
class AccessPoint:
    bssid: str
    essid: Optional[str] = None
    channel: Optional[int] = None
    encryption: Optional[str] = None
    signal: Optional[int] = None
    wps: bool = False
    mfp_required: bool = False
    bandwidth: str = ""  # "20", "40", "80", "160" MHz
    wifi_generation: str = ""  # "4" (n), "5" (ac), "6" (ax), "6E", "7" (be)
    last_seen: datetime = field(default_factory=utcnow)


@dataclass
class Station:
    mac: str
    associated_bssid: Optional[str] = None
    signal: Optional[int] = None
    last_seen: datetime = field(default_factory=utcnow)


@dataclass
class Handshake:
    bssid: str
    station_mac: str
    capture_path: str
    kind: str = "handshake"  # "handshake" (4-way EAPOL) or "pmkid"
    quality: str = ""  # crackable / partial / ...
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class GpsCoordinate:
    """GPS position for wardriving integration."""
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    accuracy: Optional[float] = None
    timestamp: datetime = field(default_factory=utcnow)
