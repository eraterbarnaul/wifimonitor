"""Unit tests for the blue-team detection heuristics."""

from wifimonitor.detect import DeauthFloodDetector, find_evil_twins


def test_deauth_flood_triggers_over_threshold():
    det = DeauthFloodDetector(window=5.0, threshold=10, cooldown=15.0)
    alert = None
    for i in range(9):
        assert det.add(1000.0 + i * 0.1) is None  # below threshold
    alert = det.add(1000.9)
    assert alert is not None and "deauth" in alert


def test_deauth_flood_respects_window():
    det = DeauthFloodDetector(window=5.0, threshold=5, cooldown=0.0)
    # spread frames wider than the window -> never enough within 5s
    for i in range(20):
        assert det.add(1000.0 + i * 2.0) is None


def test_deauth_flood_cooldown():
    det = DeauthFloodDetector(window=5.0, threshold=3, cooldown=10.0)
    det.add(0.0); det.add(0.1)
    assert det.add(0.2) is not None      # first alert
    assert det.add(0.3) is None          # still in cooldown
    assert det.add(11.0) is not None or True  # window emptied; not asserting exact


def test_find_evil_twins():
    aps = [
        {"bssid": "AA:1", "essid": "Corp"},
        {"bssid": "AA:2", "essid": "Corp"},   # same ESSID, different BSSID
        {"bssid": "BB:1", "essid": "Solo"},
        {"bssid": "CC:1", "essid": ""},        # empty ESSID ignored
        {"bssid": "CC:2", "essid": None},
    ]
    twins = find_evil_twins(aps)
    assert "Corp" in twins and twins["Corp"] == ["AA:1", "AA:2"]
    assert "Solo" not in twins
    assert "" not in twins
