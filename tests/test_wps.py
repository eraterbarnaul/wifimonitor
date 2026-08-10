"""Tests for WPS output parsing and the PMKID RSN element."""

from wifimonitor.wps_attack import parse_wps_output


def test_parse_pin():
    assert parse_wps_output("[+] WPS PIN: '12345670'") == {"pin": "12345670"}


def test_parse_psk_quoted():
    assert parse_wps_output("[+] WPA PSK: 'my secret pass'") == {"psk": "my secret pass"}


def test_parse_both_on_one_line():
    line = "WPS PIN: 12345670 WPA PSK: 'p@ss'"
    result = parse_wps_output(line)
    assert result["pin"] == "12345670"
    assert result["psk"] == "p@ss"


def test_parse_noise_returns_none():
    assert parse_wps_output("[+] Waiting for beacon from AA:BB:CC") is None
