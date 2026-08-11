"""Tests for REST API token checking."""

from wifimonitor.auth import RateLimiter, check_token, generate_token, resolve_token


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


def test_resolve_token_prefers_arg_when_no_file():
    assert resolve_token("argtoken", "") == "argtoken"


def test_resolve_token_reads_file_and_strips_whitespace(tmp_path):
    token_file = tmp_path / "token.txt"
    token_file.write_text("  filetoken\n")
    assert resolve_token("argtoken", str(token_file)) == "filetoken"


def test_resolve_token_file_wins_over_arg(tmp_path):
    token_file = tmp_path / "token.txt"
    token_file.write_text("filetoken")
    assert resolve_token("argtoken", str(token_file)) == "filetoken"


def test_resolve_token_neither_set_is_empty():
    assert resolve_token("", "") == ""


def test_rate_limiter_blocks_after_max_failures():
    limiter = RateLimiter(max_failures=3, window_seconds=60.0)
    for _ in range(3):
        assert limiter.is_blocked("1.2.3.4") is False
        limiter.record_failure("1.2.3.4")
    assert limiter.is_blocked("1.2.3.4") is True


def test_rate_limiter_keys_are_independent():
    limiter = RateLimiter(max_failures=1, window_seconds=60.0)
    limiter.record_failure("1.2.3.4")
    assert limiter.is_blocked("1.2.3.4") is True
    assert limiter.is_blocked("5.6.7.8") is False


def test_rate_limiter_success_clears_failures():
    limiter = RateLimiter(max_failures=1, window_seconds=60.0)
    limiter.record_failure("1.2.3.4")
    assert limiter.is_blocked("1.2.3.4") is True
    limiter.record_success("1.2.3.4")
    assert limiter.is_blocked("1.2.3.4") is False


def test_rate_limiter_window_expires():
    limiter = RateLimiter(max_failures=1, window_seconds=10.0)
    limiter.record_failure("1.2.3.4", now=0.0)
    assert limiter.is_blocked("1.2.3.4", now=5.0) is True
    assert limiter.is_blocked("1.2.3.4", now=15.0) is False  # outside the window
