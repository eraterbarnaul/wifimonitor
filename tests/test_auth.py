"""Tests for REST API token checking."""

from wifimonitor.auth import check_token, generate_token


def test_no_token_means_open():
    assert check_token("") is True
    assert check_token("", "Bearer whatever") is True


def test_bearer_header():
    assert check_token("secret", "Bearer secret") is True
    assert check_token("secret", "Bearer wrong") is False
    assert check_token("secret", "secret") is False  # missing "Bearer "


def test_query_token_fallback():
    assert check_token("secret", "", "secret") is True
    assert check_token("secret", "", "nope") is False


def test_missing_credentials_rejected():
    assert check_token("secret") is False
    assert check_token("secret", "", "") is False


def test_generate_token_is_nonempty_and_unique():
    a = generate_token()
    b = generate_token()
    assert a and b and a != b
