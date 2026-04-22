"""Token-bucket rate limiter for threat intelligence API calls.

Enforces per-source rate limits to avoid API bans. Thread-safe.
Default: THREAT_INTEL_RATE_LIMIT requests per minute per source.
"""

from __future__ import annotations

import threading
import time

from ..config import THREAT_INTEL_RATE_LIMIT


class RateLimiter:
    """Token-bucket rate limiter (per-source, per-minute)."""

    def __init__(self, max_per_minute: int | None = None) -> None:
        self._max = max_per_minute or THREAT_INTEL_RATE_LIMIT
        self._lock = threading.Lock()
        # source_name -> list of timestamps (epoch)
        self._buckets: dict[str, list[float]] = {}

    def acquire(self, source: str, timeout: float = 60.0) -> bool:
        """Block until a token is available, or return False on timeout.

        Args:
            source: The source name (e.g., "virustotal").
            timeout: Max seconds to wait for a token.

        Returns:
            True if acquired, False if timed out.
        """
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            with self._lock:
                now = time.time()
                bucket = self._buckets.setdefault(source, [])

                # Prune entries older than 60 seconds
                bucket[:] = [t for t in bucket if now - t < 60.0]

                if len(bucket) < self._max:
                    bucket.append(now)
                    return True

            # Wait before retry
            time.sleep(0.5)

        return False

    def remaining(self, source: str) -> int:
        """How many requests are left in the current window."""
        with self._lock:
            now = time.time()
            bucket = self._buckets.get(source, [])
            active = [t for t in bucket if now - t < 60.0]
            return max(0, self._max - len(active))

    def reset(self, source: str | None = None) -> None:
        """Reset rate limit tracking for a source (or all sources)."""
        with self._lock:
            if source:
                self._buckets.pop(source, None)
            else:
                self._buckets.clear()
