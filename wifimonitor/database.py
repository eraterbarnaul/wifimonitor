import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List

from .models import AccessPoint, Station, Handshake


class DatabaseManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
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
                    last_seen TEXT
                )
                """
            )
            ap_columns = {row[1] for row in conn.execute("PRAGMA table_info(access_points)")}
            if "wps" not in ap_columns:
                conn.execute("ALTER TABLE access_points ADD COLUMN wps INTEGER DEFAULT 0")
            if "mfp_required" not in ap_columns:
                conn.execute("ALTER TABLE access_points ADD COLUMN mfp_required INTEGER DEFAULT 0")
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
                    created_at TEXT
                )
                """
            )
            # Migrate databases created before the `kind` column existed.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(handshakes)")}
            if "kind" not in columns:
                conn.execute("ALTER TABLE handshakes ADD COLUMN kind TEXT DEFAULT 'handshake'")

    def upsert_access_point(self, ap: AccessPoint) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO access_points (bssid, essid, channel, encryption, signal, wps, mfp_required, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    essid=excluded.essid,
                    channel=excluded.channel,
                    encryption=excluded.encryption,
                    signal=excluded.signal,
                    wps=excluded.wps,
                    mfp_required=excluded.mfp_required,
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
                    ap.last_seen.isoformat(),
                ),
            )

    def upsert_station(self, station: Station) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO stations (mac, associated_bssid, signal, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    associated_bssid=excluded.associated_bssid,
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
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO handshakes (bssid, station_mac, capture_path, kind, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    handshake.bssid,
                    handshake.station_mac,
                    handshake.capture_path,
                    handshake.kind,
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
