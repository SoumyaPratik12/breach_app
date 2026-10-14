from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class InMemoryRateLimiter:
    """Thread-safe in-memory sliding-window request limiter."""

    def __init__(self, max_attempts: int, window_seconds: int):
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _purge_expired(self, now: float) -> None:
        """Remove expired attempts and inactive client entries."""
        cutoff = now - self.window_seconds
        for client_key, attempts in list(self._attempts.items()):
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if not attempts:
                self._attempts.pop(client_key, None)

    def is_limited(self, client_key: str) -> bool:
        now = monotonic()
        with self._lock:
            self._purge_expired(now)
            attempts = self._attempts.get(client_key)
            if not attempts:
                return False
            return len(attempts) >= self.max_attempts

    def record_failure(self, client_key: str) -> None:
        self.record_attempt(client_key)

    def record_attempt(self, client_key: str) -> None:
        now = monotonic()
        with self._lock:
            self._purge_expired(now)
            self._attempts[client_key].append(now)

    def reserve_if_allowed(self, client_key: str) -> float | None:
        """Reserve an attempt and return its token, or None if limited."""
        now = monotonic()
        with self._lock:
            self._purge_expired(now)
            attempts = self._attempts[client_key]
            if len(attempts) >= self.max_attempts:
                return None
            attempts.append(now)
            return now

    def release_attempt(self, client_key: str, token: float) -> None:
        """Release only the specific reservation that failed."""
        with self._lock:
            attempts = self._attempts.get(client_key)
            if not attempts:
                return
            for index, attempt in enumerate(attempts):
                if attempt == token:
                    del attempts[index]
                    break
            if not attempts:
                self._attempts.pop(client_key, None)

    def consume_if_allowed(self, client_key: str) -> bool:
        return self.reserve_if_allowed(client_key) is not None

    def reset(self) -> None:
        """Clear state for isolated tests or controlled local resets."""
        with self._lock:
            self._attempts.clear()


class LoginRateLimiter(InMemoryRateLimiter):
    """In-memory limiter for failed login attempts by client IP."""
