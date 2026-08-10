"""Tests for the plugin registry."""
from wifimonitor.plugins import (
    registry,
    DeauthAttackPlugin,
    WpsAttackPlugin,
    PmkidRequestPlugin,
    CrackPlugin,
)


def test_registry_has_builtin_plugins():
    names = registry.names
    assert "deauth" in names
    assert "wps" in names
    assert "pmkid_request" in names
    assert "crack" in names


def test_registry_get():
    cls = registry.get("deauth")
    assert cls is DeauthAttackPlugin


def test_registry_list_plugins():
    plugins = registry.list_plugins()
    assert len(plugins) >= 4
    names = [p["name"] for p in plugins]
    assert "deauth" in names


def test_deauth_plugin_properties():
    p = DeauthAttackPlugin()
    assert p.name == "deauth"
    assert p.requires_monitor is True
    assert p.requires_clients is True
    assert p.is_running() is False


def test_wps_plugin_properties():
    p = WpsAttackPlugin()
    assert p.name == "wps"
    assert p.requires_clients is False


def test_pmkid_plugin_properties():
    p = PmkidRequestPlugin()
    assert p.name == "pmkid_request"
    assert p.is_running() is False


def test_crack_plugin_no_monitor():
    p = CrackPlugin()
    assert p.name == "crack"
    assert p.requires_monitor is False
