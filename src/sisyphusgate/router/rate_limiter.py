from __future__ import annotations

import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, window_seconds: int = 60, threshold: int = 10, bucket_capacity: int = 20):
        self._window = window_seconds
        self._threshold = threshold
        self._bucket_capacity = bucket_capacity
        self._buckets: dict[str, float] = defaultdict(lambda: float(bucket_capacity))
        self._violations: dict[str, list[float]] = defaultdict(list)
        self._last_refill: dict[str, float] = {}

    def allow(self, ip: str) -> bool:
        now = time.time()
        self._refill(ip, now)

        if self._buckets[ip] >= 1.0:
            self._buckets[ip] -= 1.0
            self._record_access(ip, now)
            return True

        self._record_access(ip, now)
        return False

    def is_high_frequency(self, ip: str) -> bool:
        now = time.time()
        self._cleanup_violations(ip, now)
        return len(self._violations.get(ip, [])) >= self._threshold

    def get_access_count(self, ip: str) -> int:
        now = time.time()
        self._cleanup_violations(ip, now)
        return len(self._violations.get(ip, []))

    def _refill(self, ip: str, now: float) -> None:
        last = self._last_refill.get(ip, now)
        elapsed = now - last
        refill_rate = self._bucket_capacity / self._window
        self._buckets[ip] = min(self._bucket_capacity, self._buckets[ip] + elapsed * refill_rate)
        self._last_refill[ip] = now

    def _record_access(self, ip: str, now: float) -> None:
        self._violations[ip].append(now)
        self._cleanup_violations(ip, now)

    def _cleanup_violations(self, ip: str, now: float) -> None:
        if ip not in self._violations:
            return
        cutoff = now - self._window
        records = self._violations[ip]
        while records and records[0] < cutoff:
            records.pop(0)
        if not records:
            del self._violations[ip]

    def cleanup_all(self) -> int:
        now = time.time()
        removed = 0
        stale = []
        for ip, records in self._violations.items():
            self._cleanup_violations(ip, now)
            if ip not in self._violations:
                stale.append(ip)
                removed += 1
        for ip in stale:
            self._buckets.pop(ip, None)
            self._last_refill.pop(ip, None)
        return removed