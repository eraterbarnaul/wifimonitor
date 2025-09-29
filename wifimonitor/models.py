from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AccessPoint:
    bssid: str
    essid: Optional[str] = None
    channel: Optional[int] = None
    encryption: Optional[str] = None
    signal: Optional[int] = None
    last_seen: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Station:
    mac: str
    associated_bssid: Optional[str] = None
    signal: Optional[int] = None
    last_seen: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Handshake:
    bssid: str
    station_mac: str
    capture_path: str
    created_at: datetime = field(default_factory=datetime.utcnow)
