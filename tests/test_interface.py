"""Tests for monitor-mode idempotency (the enable-then-start bug)."""

import subprocess

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


def _fake_runner(calls, missing=()):
    """Return a _run_command stand-in that records calls and can 404 some tools."""
    def run(command, check=True):
        calls.append(command)
        if command[0] in missing:
            raise FileNotFoundError(f"Команда '{command[0]}' не найдена.")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    return run


def test_start_monitor_mode_falls_back_to_iw_when_airmon_missing():
    manager = InterfaceManager()
    manager.set_base_interface("wlan0")
    manager._is_monitor_mode = lambda iface: False  # never already in monitor mode

    calls = []
    manager._run_command = _fake_runner(calls, missing=("airmon-ng",))

    # airmon-ng is absent -> in-place switch keeps the same device name.
    assert manager.ensure_monitor_mode("wlan0") == "wlan0"
    assert manager._monitor_method == "iw"
    # airmon-ng was attempted, then the iw/ip path ran.
    assert ["airmon-ng", "start", "wlan0"] in calls
    assert ["iw", "dev", "wlan0", "set", "type", "monitor"] in calls
    assert ["ip", "link", "set", "wlan0", "down"] in calls
    assert ["ip", "link", "set", "wlan0", "up"] in calls


def test_disable_monitor_mode_iw_restores_managed():
    manager = InterfaceManager()
    manager.set_base_interface("wlan0")
    manager._is_monitor_mode = lambda iface: False

    calls = []
    manager._run_command = _fake_runner(calls, missing=("airmon-ng",))
    manager.ensure_monitor_mode("wlan0")

    calls.clear()
    manager.disable_monitor_mode()
    # Restore path uses iw (not airmon-ng) to return the device to managed mode.
    assert ["iw", "dev", "wlan0", "set", "type", "managed"] in calls
    assert not any(c[0] == "airmon-ng" for c in calls)
    assert manager.monitor_interface == "wlan0"
    assert manager._auto_started is False
    assert manager._monitor_method is None
