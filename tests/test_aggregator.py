from __future__ import annotations

import pytest

from sisyphusgate.aggregator.collector import EventCollector


class TestEventCollector:
    @pytest.mark.asyncio
    async def test_publish_and_consume(self):
        received = []

        async def consumer(event):
            received.append(event)

        collector = EventCollector(queue_size=100)
        collector.add_consumer(consumer)
        await collector.start()

        await collector.publish({"test": "data", "event_type": "test"})
        await collector.publish({"test": "data2", "event_type": "test2"})

        await collector.stop()

        assert len(received) == 2
        assert received[0]["test"] == "data"
        assert received[1]["test"] == "data2"


class TestStorage:
    def test_jsonl_storage_create(self):
        from sisyphusgate.aggregator.storage import JSONLStorage
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            _ = JSONLStorage(output_path=tmpdir, flush_interval=1)
            assert os.path.exists(tmpdir)


class TestReporter:
    def test_reporter_summary(self):
        from sisyphusgate.aggregator.collector import EventCollector
        from sisyphusgate.aggregator.geoip import GeoIPResolver
        from sisyphusgate.aggregator.reporter import Reporter

        collector = EventCollector(queue_size=100)
        geoip = GeoIPResolver(db_path=None)
        reporter = Reporter(collector, geoip)

        summary = reporter.generate_summary()
        assert "total_events" in summary
        assert "geoip_enabled" in summary
        assert summary["total_events"] == 0