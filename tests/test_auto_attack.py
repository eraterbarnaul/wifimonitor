"""Tests for the auto-attack pipeline."""
import time
from unittest.mock import patch, MagicMock
from pathlib import Path

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
        pipeline.notify_handshake("/tmp/test.pcap")
        time.sleep(2.0)
    assert any(ok for ok, _ in complete_events)


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
