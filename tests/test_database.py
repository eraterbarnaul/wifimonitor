"""Full coverage tests for wifimonitor.database module."""

import threading

import pytest

from wifimonitor.database import DatabaseManager
from wifimonitor.models import AccessPoint, Handshake, Station


@pytest.fixture
def db(tmp_path):
    """Create a fresh DatabaseManager for each test."""
    return DatabaseManager(tmp_path / "test.db")


def _make_ap(bssid="AA:BB:CC:DD:EE:FF", essid="TestNet", channel=6, encryption="WPA2", signal=-50):
    return AccessPoint(bssid=bssid, essid=essid, channel=channel, encryption=encryption, signal=signal)


def _make_station(mac="11:22:33:44:55:66", bssid="AA:BB:CC:DD:EE:FF"):
    return Station(mac=mac, associated_bssid=bssid, signal=-60)


def _make_handshake(bssid="AA:BB:CC:DD:EE:FF", station_mac="11:22:33:44:55:66"):
    return Handshake(bssid=bssid, station_mac=station_mac, capture_path="/tmp/test.pcap", kind="handshake")


class TestWalMode:
    def test_wal_mode_enabled(self, db):
        """WAL journal mode should be set on connection."""
        with db._connect() as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "wal"


class TestUpsertAccessPoint:
    def test_insert_and_fetch(self, db):
        ap = _make_ap()
        db.upsert_access_point(ap)
        rows = db.fetch_access_points()
        assert len(rows) == 1
        assert rows[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert rows[0]["essid"] == "TestNet"

    def test_rate_limiting_skips_second_call(self, db):
        ap = _make_ap(signal=-50)
        db.upsert_access_point(ap)

        # Immediately update with different signal — should be skipped
        ap2 = _make_ap(signal=-30)
        db.upsert_access_point(ap2)

        rows = db.fetch_access_points()
        assert len(rows) == 1
        assert rows[0]["signal"] == -50  # Original value kept

    def test_force_bypasses_rate_limit(self, db):
        ap = _make_ap(signal=-50)
        db.upsert_access_point(ap)

        # Force update immediately
        ap2 = _make_ap(signal=-30)
        db.upsert_access_point_force(ap2)

        rows = db.fetch_access_points()
        assert len(rows) == 1
        assert rows[0]["signal"] == -30  # Updated


class TestUpsertStation:
    def test_insert_and_fetch(self, db):
        station = _make_station()
        db.upsert_station(station)
        rows = db.fetch_stations()
        assert len(rows) == 1
        assert rows[0]["mac"] == "11:22:33:44:55:66"

    def test_rate_limiting(self, db):
        station = _make_station()
        db.upsert_station(station)

        # Second call immediately should be skipped
        station2 = Station(mac="11:22:33:44:55:66", associated_bssid="FF:FF:FF:FF:FF:FF", signal=-40)
        db.upsert_station(station2)

        rows = db.fetch_stations()
        assert len(rows) == 1
        assert rows[0]["associated_bssid"] == "AA:BB:CC:DD:EE:FF"  # Original


class TestAddHandshake:
    def test_add_and_fetch(self, db):
        hs = _make_handshake()
        db.add_handshake(hs)
        rows = db.fetch_handshakes()
        assert len(rows) == 1
        assert rows[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert rows[0]["kind"] == "handshake"

    def test_multiple_handshakes(self, db):
        db.add_handshake(_make_handshake())
        db.add_handshake(Handshake(
            bssid="AA:BB:CC:DD:EE:FF",
            station_mac="22:33:44:55:66:77",
            capture_path="/tmp/test2.pcap",
            kind="pmkid",
        ))
        rows = db.fetch_handshakes()
        assert len(rows) == 2


class TestFetch:
    def test_fetch_access_points_empty(self, db):
        assert db.fetch_access_points() == []

    def test_fetch_stations_empty(self, db):
        assert db.fetch_stations() == []

    def test_fetch_handshakes_empty(self, db):
        assert db.fetch_handshakes() == []


class TestSessions:
    def test_create_session(self, db):
        sid = db.create_session("wlan0", notes="test session")
        assert sid is not None
        assert sid > 0

    def test_end_session(self, db):
        sid = db.create_session("wlan0")
        db.end_session(sid)
        sessions = db.fetch_sessions()
        assert sessions[0]["ended_at"] is not None

    def test_snapshot_session(self, db):
        sid = db.create_session("wlan0")
        aps = [{"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Net1", "channel": 6, "encryption": "WPA2", "signal": -50}]
        stations = [{"mac": "11:22:33:44:55:66", "associated_bssid": "AA:BB:CC:DD:EE:FF"}]
        db.snapshot_session(sid, aps, stations)

        with db._connect() as conn:
            rows = list(conn.execute("SELECT * FROM session_snapshots WHERE session_id=?", (sid,)))
        assert len(rows) == 1
        assert rows[0]["client_count"] == 1

    def test_compare_sessions(self, db):
        sid1 = db.create_session("wlan0")
        aps1 = [
            {"bssid": "AA:BB:CC:DD:EE:01", "essid": "Net1", "channel": 6, "encryption": "WPA2", "signal": -50},
            {"bssid": "AA:BB:CC:DD:EE:02", "essid": "Net2", "channel": 11, "encryption": "WPA2", "signal": -60},
        ]
        db.snapshot_session(sid1, aps1, [])

        sid2 = db.create_session("wlan0")
        aps2 = [
            {"bssid": "AA:BB:CC:DD:EE:01", "essid": "Net1", "channel": 6, "encryption": "WPA3", "signal": -50},
            {"bssid": "AA:BB:CC:DD:EE:03", "essid": "Net3", "channel": 1, "encryption": "Open", "signal": -70},
        ]
        db.snapshot_session(sid2, aps2, [])

        result = db.compare_sessions(sid1, sid2)
        assert len(result["new"]) == 1
        assert result["new"][0]["bssid"] == "AA:BB:CC:DD:EE:03"
        assert len(result["gone"]) == 1
        assert result["gone"][0]["bssid"] == "AA:BB:CC:DD:EE:02"
        assert len(result["changed"]) == 1
        assert result["changed"][0]["bssid"] == "AA:BB:CC:DD:EE:01"
        assert result["changed"][0]["changes"]["encryption"]["before"] == "WPA2"
        assert result["changed"][0]["changes"]["encryption"]["after"] == "WPA3"


class TestThreadSafety:
    def test_concurrent_writes(self, db):
        """Multiple threads writing concurrently should not corrupt the database."""
        errors = []

        def writer(thread_id):
            try:
                for i in range(20):
                    ap = AccessPoint(
                        bssid=f"AA:BB:CC:DD:{thread_id:02X}:{i:02X}",
                        essid=f"Net_{thread_id}_{i}",
                        channel=6,
                        encryption="WPA2",
                        signal=-50,
                    )
                    db.upsert_access_point_force(ap)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        rows = db.fetch_access_points()
        assert len(rows) == 100  # 5 threads * 20 APs each
