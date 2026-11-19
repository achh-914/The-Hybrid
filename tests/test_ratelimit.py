import pytest

from hybrid.ratelimit import RateLimiter, env_int


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_allows_up_to_the_limit_then_returns_the_wait_time():
    clock = Clock()
    rl = RateLimiter(2, 60, clock=clock)
    assert rl.claim("t1") == 0
    assert rl.claim("t1") == 0
    wait = rl.claim("t1")
    assert 0 < wait <= 60


def test_calls_are_allowed_again_after_the_window():
    clock = Clock()
    rl = RateLimiter(1, 60, clock=clock)
    assert rl.claim("t1") == 0
    assert rl.claim("t1") > 0
    clock.now += 61
    assert rl.claim("t1") == 0


def test_a_refused_call_is_not_recorded():
    clock = Clock()
    rl = RateLimiter(1, 60, clock=clock)
    rl.claim("t1")
    for _ in range(5):
        assert rl.claim("t1") > 0
    clock.now += 61
    assert rl.claim("t1") == 0


def test_keys_do_not_share_a_budget():
    rl = RateLimiter(1, 60, clock=Clock())
    assert rl.claim("t1") == 0
    assert rl.claim("t2") == 0
    assert rl.claim("t1") > 0


def test_invalid_settings_are_refused():
    with pytest.raises(ValueError):
        RateLimiter(0, 60)
    with pytest.raises(ValueError):
        RateLimiter(1, 0)


def test_env_int_falls_back_on_bad_values(monkeypatch):
    monkeypatch.delenv("X_LIMIT", raising=False)
    assert env_int("X_LIMIT", 30) == 30
    for bad in ("abc", "0", "-3", ""):
        monkeypatch.setenv("X_LIMIT", bad)
        assert env_int("X_LIMIT", 30) == 30
    monkeypatch.setenv("X_LIMIT", "7")
    assert env_int("X_LIMIT", 30) == 7
