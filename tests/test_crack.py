"""Tests for aircrack-ng output parsing."""

from wifimonitor.crack import parse_aircrack_output


def test_key_found():
    assert parse_aircrack_output("KEY FOUND! [ mypassword ]") == {"key": "mypassword"}
    assert parse_aircrack_output("KEY FOUND! [ p@ss w0rd ]") == {"key": "p@ss w0rd"}


def test_progress():
    result = parse_aircrack_output("[00:00:12] 4500/9000 keys tested (1234.56 k/s)")
    assert result == {"progress": "4500/9000 (50.0%)"}


def test_progress_with_thousands_separator():
    result = parse_aircrack_output("[00:01:00] 1,000/10,000 keys tested (999 k/s)")
    assert result == {"progress": "1000/10000 (10.0%)"}


def test_noise_returns_none():
    assert parse_aircrack_output("Reading packets, please wait...") is None
    assert parse_aircrack_output("") is None
