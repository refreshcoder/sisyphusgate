from __future__ import annotations

from typing import Any

from sisyphusgate.aggregator.collector import EventCollector
from sisyphusgate.aggregator.geoip import GeoIPResolver
from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class Reporter:
    def __init__(self, collector: EventCollector, geoip: GeoIPResolver):
        self._collector = collector
        self._geoip = geoip

    def generate_summary(self) -> dict[str, Any]:
        return {
            "total_events": self._collector.total_events,
            "queue_size": self._collector.queue_size,
            "geoip_enabled": self._geoip.is_enabled,
        }

    def format_summary(self) -> str:
        summary = self.generate_summary()
        lines = [
            "=" * 60,
            "  SisyphusGate - System Summary",
            "=" * 60,
            f"  Total Events Processed: {summary['total_events']}",
            f"  Event Queue Size:       {summary['queue_size']}",
            f"  GeoIP Enabled:          {summary['geoip_enabled']}",
            "=" * 60,
        ]
        return "\n".join(lines)