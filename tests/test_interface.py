"""Tests for monitor-mode idempotency (the enable-then-start bug)."""

from wifimonitor.interface import InterfaceManager


def test_ensure_monitor_mode_reuses_active_monitor():
    manager = InterfaceManager()
    manager.set_base_interface("wlan0")

    calls = {"start": 0}
    # Only the renamed monitor device reports monitor mode.
    manager._is_monitor_mode = lambda iface: iface == "wlan0mon"

    def fake_start(iface):
        calls["start"] += 1
        return f"monitor mode vif enabled for [phy0]{iface} on [phy0]wlan0mon"

    manager._start_monitor_mode = fake_start

    # Enable: airmon-ng renames wlan0 -> wlan0mon.
    assert manager.ensure_monitor_mode("wlan0") == "wlan0mon"
    assert calls["start"] == 1

    # Start after Enable: the controller passes the original base name again;
    # it must reuse the active monitor, not try to re-enable the missing wlan0.
    assert manager.ensure_monitor_mode("wlan0") == "wlan0mon"
    assert calls["start"] == 1


def test_ensure_monitor_mode_uses_already_monitor_base():
    manager = InterfaceManager()
    manager.set_base_interface("wlan1mon")
    manager._is_monitor_mode = lambda iface: iface == "wlan1mon"
    manager._start_monitor_mode = lambda iface: (_ for _ in ()).throw(AssertionError("should not start"))
    assert manager.ensure_monitor_mode("wlan1mon") == "wlan1mon"
    assert manager._auto_started is False
