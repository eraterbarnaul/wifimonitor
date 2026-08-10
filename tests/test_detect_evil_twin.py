"""Tests for the EvilTwinDetector."""
from wifimonitor.detect import EvilTwinDetector


def test_single_ap_no_alert():
    det = EvilTwinDetector()
    result = det.check("aa:bb:cc:dd:ee:ff", "TestNet", channel=6, timestamp=1.0)
    assert result is None


def test_two_bssids_same_essid_triggers_alert():
    det = EvilTwinDetector()
    det.check("aa:bb:cc:dd:ee:01", "MyNet", channel=6, timestamp=1.0)
    alert = det.check("aa:bb:cc:dd:ee:02", "MyNet", channel=6, timestamp=2.0)
    assert alert is not None
    assert "Evil Twin" in alert
    assert "MyNet" in alert


def test_cooldown_prevents_repeated_alerts():
    det = EvilTwinDetector(cooldown=60.0)
    det.check("aa:bb:cc:dd:ee:01", "Net", channel=1, timestamp=1.0)
    alert1 = det.check("aa:bb:cc:dd:ee:02", "Net", channel=1, timestamp=2.0)
    assert alert1 is not None
    # Third BSSID within cooldown
    alert2 = det.check("aa:bb:cc:dd:ee:03", "Net", channel=1, timestamp=3.0)
    assert alert2 is None  # Suppressed by cooldown


def test_encryption_change_detection():
    det = EvilTwinDetector()
    det.check("aa:bb:cc:dd:ee:01", "SecureNet", channel=6, encryption="WPA2", timestamp=1.0)
    alert = det.check("aa:bb:cc:dd:ee:01", "SecureNet", channel=6, encryption="OPEN", timestamp=70.0)
    assert alert is not None
    assert "шифрование" in alert


def test_no_essid_no_alert():
    det = EvilTwinDetector()
    result = det.check("aa:bb:cc:dd:ee:ff", None, channel=6, timestamp=1.0)
    assert result is None


def test_no_bssid_no_alert():
    det = EvilTwinDetector()
    result = det.check("", "TestNet", channel=6, timestamp=1.0)
    assert result is None
