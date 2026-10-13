from app.security.login_rate_limiter import LoginRateLimiter


def test_limiter_allows_requests_below_threshold():
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=900)

    for _ in range(4):
        limiter.record_failure("client-a")

    assert limiter.is_limited("client-a") is False


def test_limiter_blocks_at_threshold():
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=900)

    for _ in range(5):
        limiter.record_failure("client-a")

    assert limiter.is_limited("client-a") is True


def test_limiter_tracks_clients_separately():
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=900)
    limiter.record_failure("client-a")
    limiter.record_failure("client-a")

    assert limiter.is_limited("client-a") is True
    assert limiter.is_limited("client-b") is False


def test_limiter_expires_attempts_outside_window(monkeypatch):
    current_time = 0.0
    monkeypatch.setattr(
        "app.security.login_rate_limiter.monotonic",
        lambda: current_time,
    )
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=10)
    limiter.record_failure("client-a")

    current_time = 9.0
    limiter.record_failure("client-a")
    assert limiter.is_limited("client-a") is True

    current_time = 10.0
    assert limiter.is_limited("client-a") is False


def test_reset_clears_limiter_state():
    limiter = LoginRateLimiter(max_attempts=1, window_seconds=900)
    limiter.record_failure("client-a")
    assert limiter.is_limited("client-a") is True

    limiter.reset()

    assert limiter.is_limited("client-a") is False


def test_expired_inactive_clients_are_cleaned_up(monkeypatch):
    current_time = 0.0
    monkeypatch.setattr(
        "app.security.login_rate_limiter.monotonic",
        lambda: current_time,
    )
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=10)
    limiter.record_failure("inactive-client")
    current_time = 11.0
    limiter.record_failure("active-client")

    # The inactive client's expired entry should also be removed.
    assert "inactive-client" not in limiter._attempts
    assert "active-client" in limiter._attempts
