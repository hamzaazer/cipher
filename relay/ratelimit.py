"""In-memory rate limiting for the only request that allocates storage.

The limiter keeps a short-lived client key in RAM and nothing else.  It is a
blunt DoS mitigation, not an identity: behind a reverse proxy the proxy's
address is the key unless it is configured to pass the real client through.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        if self.limit <= 0:
            return True
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                if len(self._hits) >= self.max_keys:
                    self._prune_locked(cutoff)
                    if len(self._hits) >= self.max_keys:
                        self._hits.pop(next(iter(self._hits)), None)
                bucket = deque()
                self._hits[key] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True

    def _prune_locked(self, cutoff: float) -> None:
        empty = [key for key, bucket in self._hits.items() if not bucket or bucket[-1] <= cutoff]
        for key in empty:
            del self._hits[key]
