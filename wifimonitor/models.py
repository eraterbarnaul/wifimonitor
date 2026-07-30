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
