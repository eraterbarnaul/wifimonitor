"""Tests for the auto-attack pipeline."""
import time
from unittest.mock import patch, MagicMock

from wifimonitor.auto_attack import AutoAttackPipeline, AutoAttackPhase


def test_pipeline_starts_and_stops(tmp_path):
    pipeline = AutoAttackPipeline(
        interface="wlan0mon",
        capture_dir=tmp_path,
        try_pmkid_first=False,
        deauth_rounds=1,
        handshake_timeout=1.0,
    )
    with patch("wifimonitor.deauth.DeauthService") as MockDeauth:
        mock_svc = MockDeauth.return_value
        mock_svc.start = MagicMock()
        mock_svc.stop = MagicMock()
        pipeline.start("aa:bb:cc:dd:ee:ff", ["11:22:33:44:55:66"], channel=6)
        time.sleep(0.5)
        pipeline.stop()
        assert not pipeline.is_running()


def test_notify_handshake_completes_pipeline(tmp_path):
    complete_events = []
    pipeline = AutoAttackPipeline(
        interface="wlan0mon",
        capture_dir=tmp_path,
        on_complete=lambda ok, m: complete_events.append((ok, m)),
        try_pmkid_first=False,
        deauth_rounds=3,
        handshake_timeout=10.0,
    )
    with patch("wifimonitor.deauth.sendp"):
        pipeline.start("aa:bb:cc:dd:ee:ff", ["11:22:33:44:55:66"])
        time.sleep(0.5)
        pipeline.notify_handshake("/tmp/test.pcap", "aa:bb:cc:dd:ee:ff")
        time.sleep(2.0)
    assert any(ok for ok, _ in complete_events)


def test_notify_handshake_ignores_other_bssid(tmp_path):
    """A handshake captured for an unrelated AP must not be mistaken for this

    pipeline's own target (e.g. two APs sharing a channel while this one is
    locked to it for the attack).
    """
    complete_events = []
    pipeline = AutoAttackPipeline(
        interface="wlan0mon",
        capture_dir=tmp_path,
        on_complete=lambda ok, m: complete_events.append((ok, m)),
        try_pmkid_first=False,
        deauth_rounds=1,
        deauth_interval=0.05,  # keep _do_deauth's fixed 2*interval+1.0s block short
        handshake_timeout=0.5,
    )
    with patch("wifimonitor.deauth.sendp"):
        pipeline.start("aa:bb:cc:dd:ee:ff", ["11:22:33:44:55:66"])
        time.sleep(0.2)
        pipeline.notify_handshake("/tmp/unrelated.pcap", "11:11:11:11:11:11")
        time.sleep(2.5)
    # The unrelated handshake must not have completed the pipeline; it should
    # time out and report failure instead of a false success.
    assert any(not ok for ok, _ in complete_events)
    assert not any(ok for ok, _ in complete_events)


def test_failure_when_no_handshake(tmp_path):
    complete_events = []
    pipeline = AutoAttackPipeline(
        interface="wlan0mon",
        capture_dir=tmp_path,
        on_complete=lambda ok, m: complete_events.append((ok, m)),
        try_pmkid_first=False,
        deauth_rounds=1,
        handshake_timeout=0.5,
    )
    # No clients, no deauth - should fail
    pipeline.start("aa:bb:cc:dd:ee:ff", [], channel=6)
    time.sleep(2.0)
    assert any(not ok for ok, _ in complete_events)


def test_phase_property(tmp_path):
    pipeline = AutoAttackPipeline(interface="wlan0mon", capture_dir=tmp_path)
    assert pipeline.phase == AutoAttackPhase.IDLE
