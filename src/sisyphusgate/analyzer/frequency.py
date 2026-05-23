from __future__ import annotations

import time
from collections import defaultdict


class FrequencyTracker:
    def __init__(self, window_seconds: int = 60, threshold: int = 10):
        self._window = window_seconds
        self._threshold = threshold
        self._records: dict[str, list[float]] = defaultdict(list)

    def record(self, ip: str) -> int:
        now = time.time()
        self._records[ip].append(now)
        self._cleanup(ip, now)
        return len(self._records[ip])

    def get_count(self, ip: str) -> int:
        now = time.time()
        if ip in self._records:
            self._cleanup(ip, now)
            return len(self._records[ip])
        return 0

    def is_high_frequency(self, ip: str) -> bool:
        return self.get_count(ip) >= self._threshold

    def get_frequency_score(self, ip: str) -> int:
        count = self.get_count(ip)
        if count >= self._threshold:
            ratio = min(count / self._threshold, 3.0)
            return int(50 + ratio * 30)
        ratio = count / max(self._threshold, 1)
        return int(ratio * 40)

    def _cleanup(self, ip: str, now: float) -> None:
        cutoff = now - self._window
        records = self._records[ip]
        while records and records[0] < cutoff:
            records.pop(0)
        if not records:
            del self._records[ip]

    def cleanup_all(self) -> int:
        now = time.time()
        removed = 0
        stale_ips = []
        for ip, records in self._records.items():
            self._cleanup(ip, now)
            if ip not in self._records:
                stale_ips.append(ip)
                removed += 1
        return removed

    def get_top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        now = time.time()
        counts = []
        for ip, records in self._records.items():
            self._cleanup(ip, now)
            if ip in self._records and self._records[ip]:
                counts.append((ip, len(self._records[ip])))
        counts.sort(key=lambda x: x[1], reverse=True)
        return counts[:n]