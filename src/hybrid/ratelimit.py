from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding-window limiter per key, kept in memory.

    Single process only: with several workers each one counts on its own.
    """

    def __init__(self, max_calls: int, window_seconds: float, clock=time.monotonic):
        if max_calls < 1 or window_seconds <= 0:
            raise ValueError("max_calls must be >= 1 and window_seconds must be > 0")
        self._max = max_calls
        self._window = window_seconds
        self._clock = clock
        self._calls: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def claim(self, key: str) -> float:
        """Record a call and return 0, or return the seconds to wait (call not recorded)."""
        now = self._clock()
        with self._lock:
            calls = self._calls[key]
            while calls and now - calls[0] >= self._window:
                calls.popleft()
            if len(calls) >= self._max:
                return self._window - (now - calls[0])
            calls.append(now)
            return 0.0


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 1 else default
