from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class LoginRateLimiter:
    """In-memory limiter for failed login attempts by client IP."""

    def __init__(self, max_attempts: int, window_seconds: int):
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def is_limited(self, client_key: str) -> bool:
        now = monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            attempts = self._attempts[client_key]
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if not attempts:
                self._attempts.pop(client_key, None)
                return False
            return len(attempts) >= self.max_attempts

    def record_failure(self, client_key: str) -> None:
        now = monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            attempts = self._attempts[client_key]
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            attempts.append(now)

    def reset(self) -> None:
        """Clear state for isolated tests or controlled local resets."""
        with self._lock:
            self._attempts.clear()
