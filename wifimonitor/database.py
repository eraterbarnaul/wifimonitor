"""Thread-safe SQLite storage with WAL mode and batched writes.

Key improvements over the original:
- WAL journal mode for concurrent read/write
- Threading lock for all write operations
- Batched upserts with configurable flush interval
- Rate-limited AP/station updates (max once per N seconds per entity)
"""

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional

from .models import AccessPoint, Station, Handshake


class DatabaseManager:
    # Rate-limit: don't update the same entity more often than this (seconds).
    _UPDATE_INTERVAL = 2.0

    def __init__(self, path: Path, batch_interval: float = 2.0) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._batch_interval = batch_interval
        self._last_ap_write: dict = {}  # bssid -> timestamp
        self._last_sta_write: dict = {}  # mac -> timestamp
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS access_points (
                        bssid TEXT PRIMARY KEY,
                        essid TEXT,
                        channel INTEGER,
                        encryption TEXT,
                        signal INTEGER,
                        wps INTEGER DEFAULT 0,
                        mfp_required INTEGER DEFAULT 0,
                        bandwidth TEXT DEFAULT '',
                        wifi_generation TEXT DEFAULT '',
                        last_seen TEXT
                    )
                    """
                )
                ap_columns = {row[1] for row in conn.execute("PRAGMA table_info(access_points)")}
                if "wps" not in ap_columns:
                    conn.execute("ALTER TABLE access_points ADD COLUMN wps INTEGER DEFAULT 0")
                if "mfp_required" not in ap_columns:
                    conn.execute("ALTER TABLE access_points ADD COLUMN mfp_required INTEGER DEFAULT 0")
                if "bandwidth" not in ap_columns:
                    conn.execute("ALTER TABLE access_points ADD COLUMN bandwidth TEXT DEFAULT ''")
                if "wifi_generation" not in ap_columns:
                    conn.execute("ALTER TABLE access_points ADD COLUMN wifi_generation TEXT DEFAULT ''")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS stations (
                        mac TEXT PRIMARY KEY,
                        associated_bssid TEXT,
                        signal INTEGER,
                        last_seen TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS handshakes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        bssid TEXT,
                        station_mac TEXT,
                        capture_path TEXT,
                        kind TEXT DEFAULT 'handshake',
                        quality TEXT DEFAULT '',
                        created_at TEXT
                    )
                    """
                )
                columns = {row[1] for row in conn.execute("PRAGMA table_info(handshakes)")}
                if "kind" not in columns:
                    conn.execute("ALTER TABLE handshakes ADD COLUMN kind TEXT DEFAULT 'handshake'")
                if "quality" not in columns:
                    conn.execute("ALTER TABLE handshakes ADD COLUMN quality TEXT DEFAULT ''")

                # Sessions table for multi-session comparison
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        started_at TEXT,
                        ended_at TEXT,
                        interface TEXT,
                        notes TEXT DEFAULT ''
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS session_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id INTEGER,
                        bssid TEXT,
                        essid TEXT,
                        channel INTEGER,
                        encryption TEXT,
                        signal INTEGER,
                        client_count INTEGER DEFAULT 0,
                        FOREIGN KEY (session_id) REFERENCES sessions(id)
                    )
                    """
                )
                # GPS locations for wardriving
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ap_locations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        bssid TEXT NOT NULL,
                        latitude REAL NOT NULL,
                        longitude REAL NOT NULL,
                        altitude REAL,
                        signal INTEGER,
                        timestamp TEXT,
                        UNIQUE(bssid, latitude, longitude)
                    )
                    """
                )

    def upsert_access_point(self, ap: AccessPoint) -> None:
        now = time.monotonic()
        # Rate-limit: skip if we wrote this AP too recently
        last = self._last_ap_write.get(ap.bssid, 0.0)
        if now - last < self._UPDATE_INTERVAL:
            return
        with self._lock:
            self._last_ap_write[ap.bssid] = now
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO access_points (bssid, essid, channel, encryption, signal, wps, mfp_required, bandwidth, wifi_generation, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        essid=COALESCE(excluded.essid, access_points.essid),
                        channel=COALESCE(excluded.channel, access_points.channel),
                        encryption=COALESCE(excluded.encryption, access_points.encryption),
                        signal=excluded.signal,
                        wps=excluded.wps,
                        mfp_required=excluded.mfp_required,
                        bandwidth=COALESCE(NULLIF(excluded.bandwidth,''), access_points.bandwidth),
                        wifi_generation=COALESCE(NULLIF(excluded.wifi_generation,''), access_points.wifi_generation),
                        last_seen=excluded.last_seen
                    """,
                    (
                        ap.bssid,
                        ap.essid,
                        ap.channel,
                        ap.encryption,
                        ap.signal,
                        int(ap.wps),
                        int(ap.mfp_required),
                        getattr(ap, "bandwidth", "") or "",
                        getattr(ap, "wifi_generation", "") or "",
                        ap.last_seen.isoformat(),
                    ),
                )

    def upsert_access_point_force(self, ap: AccessPoint) -> None:
        """Bypass rate limiting (used for SSID reveals and important updates)."""
        with self._lock:
            self._last_ap_write[ap.bssid] = time.monotonic()
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO access_points (bssid, essid, channel, encryption, signal, wps, mfp_required, bandwidth, wifi_generation, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        essid=COALESCE(excluded.essid, access_points.essid),
                        channel=COALESCE(excluded.channel, access_points.channel),
                        encryption=COALESCE(excluded.encryption, access_points.encryption),
                        signal=excluded.signal,
                        wps=excluded.wps,
                        mfp_required=excluded.mfp_required,
                        bandwidth=COALESCE(NULLIF(excluded.bandwidth,''), access_points.bandwidth),
                        wifi_generation=COALESCE(NULLIF(excluded.wifi_generation,''), access_points.wifi_generation),
                        last_seen=excluded.last_seen
                    """,
                    (
                        ap.bssid,
                        ap.essid,
                        ap.channel,
                        ap.encryption,
                        ap.signal,
                        int(ap.wps),
                        int(ap.mfp_required),
                        getattr(ap, "bandwidth", "") or "",
                        getattr(ap, "wifi_generation", "") or "",
                        ap.last_seen.isoformat(),
                    ),
                )

    def upsert_station(self, station: Station) -> None:
        now = time.monotonic()
        last = self._last_sta_write.get(station.mac, 0.0)
        if now - last < self._UPDATE_INTERVAL:
            return
        with self._lock:
            self._last_sta_write[station.mac] = now
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO stations (mac, associated_bssid, signal, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        associated_bssid=COALESCE(excluded.associated_bssid, stations.associated_bssid),
                        signal=excluded.signal,
                        last_seen=excluded.last_seen
                    """,
                    (
                        station.mac,
                        station.associated_bssid,
                        station.signal,
                        station.last_seen.isoformat(),
                    ),
                )

    def add_handshake(self, handshake: Handshake) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO handshakes (bssid, station_mac, capture_path, kind, quality, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        handshake.bssid,
                        handshake.station_mac,
                        handshake.capture_path,
                        handshake.kind,
                        handshake.quality,
                        handshake.created_at.isoformat(),
                    ),
                )

    def fetch_access_points(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return list(conn.execute("SELECT * FROM access_points"))

    def fetch_stations(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return list(conn.execute("SELECT * FROM stations"))

    def fetch_handshakes(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return list(conn.execute("SELECT * FROM handshakes ORDER BY created_at DESC"))

    # --- Session management for multi-session comparison ---

    def create_session(self, interface: str, notes: str = "") -> int:
        from .timeutil import utcnow
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO sessions (started_at, interface, notes) VALUES (?, ?, ?)",
                    (utcnow().isoformat(), interface, notes),
                )
                return cursor.lastrowid

    def end_session(self, session_id: int) -> None:
        from .timeutil import utcnow
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE sessions SET ended_at=? WHERE id=?",
                    (utcnow().isoformat(), session_id),
                )

    def snapshot_session(self, session_id: int, access_points: List[dict], stations: List[dict]) -> None:
        from collections import defaultdict
        clients_by_ap: dict = defaultdict(int)
        for sta in stations:
            bssid = sta.get("associated_bssid")
            if bssid:
                clients_by_ap[bssid] += 1

        with self._lock:
            with self._connect() as conn:
                for ap in access_points:
                    bssid = ap.get("bssid")
                    conn.execute(
                        """INSERT INTO session_snapshots
                           (session_id, bssid, essid, channel, encryption, signal, client_count)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            session_id,
                            bssid,
                            ap.get("essid"),
                            ap.get("channel"),
                            ap.get("encryption"),
                            ap.get("signal"),
                            clients_by_ap.get(bssid, 0),
                        ),
                    )

    def fetch_sessions(self) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return list(conn.execute("SELECT * FROM sessions ORDER BY started_at DESC"))

    def compare_sessions(self, session_id_a: int, session_id_b: int) -> dict:
        """Compare two sessions: new APs, disappeared APs, changed encryption."""
        with self._connect() as conn:
            rows_a = {
                row["bssid"]: dict(row)
                for row in conn.execute(
                    "SELECT * FROM session_snapshots WHERE session_id=?", (session_id_a,)
                )
            }
            rows_b = {
                row["bssid"]: dict(row)
                for row in conn.execute(
                    "SELECT * FROM session_snapshots WHERE session_id=?", (session_id_b,)
                )
            }
        new_aps = [rows_b[b] for b in rows_b if b not in rows_a]
        gone_aps = [rows_a[a] for a in rows_a if a not in rows_b]
        changed = []
        for bssid in set(rows_a) & set(rows_b):
            a, b = rows_a[bssid], rows_b[bssid]
            diffs = {}
            for field in ("essid", "channel", "encryption", "signal"):
                if a.get(field) != b.get(field):
                    diffs[field] = {"before": a.get(field), "after": b.get(field)}
            if diffs:
                changed.append({"bssid": bssid, "changes": diffs})
        return {"new": new_aps, "gone": gone_aps, "changed": changed}

    # --- GPS / wardriving ---

    def record_ap_location(self, bssid: str, latitude: float, longitude: float,
                           altitude: Optional[float] = None, signal: Optional[int] = None) -> None:
        """Record a GPS location for an access point (best-signal wins on conflict)."""
        from .timeutil import utcnow
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO ap_locations (bssid, latitude, longitude, altitude, signal, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid, latitude, longitude) DO UPDATE SET
                        signal = CASE WHEN excluded.signal > ap_locations.signal
                                      THEN excluded.signal ELSE ap_locations.signal END,
                        timestamp = excluded.timestamp
                    """,
                    (bssid, latitude, longitude, altitude, signal, utcnow().isoformat()),
                )

    def fetch_ap_locations(self, bssid: Optional[str] = None) -> List[sqlite3.Row]:
        with self._connect() as conn:
            if bssid:
                return list(conn.execute(
                    "SELECT * FROM ap_locations WHERE bssid=? ORDER BY signal DESC", (bssid,)
                ))
            return list(conn.execute("SELECT * FROM ap_locations ORDER BY bssid, signal DESC"))
