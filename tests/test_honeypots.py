from __future__ import annotations

import pytest

from sisyphusgate.honeypots.external.log_bridge import LogBridge
from sisyphusgate.honeypots.external.manager import ExternalHoneypotManager


class TestExternalHoneypotManager:
    @pytest.mark.asyncio
    async def test_instantiation(self):
        mgr = ExternalHoneypotManager()
        assert mgr is not None
        assert not mgr._running

    @pytest.mark.asyncio
    async def test_stop_without_start(self):
        mgr = ExternalHoneypotManager()
        await mgr.stop_all()

    @pytest.mark.asyncio
    async def test_health_check_empty(self):
        mgr = ExternalHoneypotManager()
        result = await mgr.health_check()
        assert isinstance(result, dict)


class TestLogBridge:
    @pytest.mark.asyncio
    async def test_instantiation(self):
        bridge = LogBridge()
        assert bridge is not None
        assert not bridge._running

    @pytest.mark.asyncio
    async def test_add_log_source(self):
        bridge = LogBridge()
        bridge.add_log_source("cowrie", "/tmp/test_cowrie.json")
        assert len(bridge._log_paths) == 1

    @pytest.mark.asyncio
    async def test_set_publish_callback(self):
        received = []

        async def cb(event):
            received.append(event)

        bridge = LogBridge(publish_callback=cb)
        assert bridge._publish is not None

    @pytest.mark.asyncio
    async def test_cowrie_line_parsing(self):
        import json

        received = []

        async def cb(event):
            received.append(event)

        bridge = LogBridge(publish_callback=cb)

        cowrie_json = json.dumps({
            "eventid": "cowrie.login.success",
            "src_ip": "10.0.0.1",
            "src_port": 54321,
            "session": "abc123",
            "username": "root",
            "password": "password123",
            "timestamp": "2026-05-21T08:00:00",
        })

        await bridge._process_cowrie_line(cowrie_json)
        assert len(received) == 1
        assert received[0]["event_type"] == "auth_success"
        assert received[0]["source_ip"] == "10.0.0.1"
        assert received[0]["honeypot_type"] == "cowrie"

    @pytest.mark.asyncio
    async def test_cowrie_command_parsing(self):
        import json

        received = []

        async def cb(event):
            received.append(event)

        bridge = LogBridge(publish_callback=cb)

        cowrie_json = json.dumps({
            "eventid": "cowrie.command.input",
            "src_ip": "10.0.0.2",
            "session": "def456",
            "input": "cat /etc/passwd",
            "timestamp": "2026-05-21T08:01:00",
        })

        await bridge._process_cowrie_line(cowrie_json)
        assert len(received) == 1
        assert received[0]["event_type"] == "command"
        assert received[0]["honeypot_type"] == "cowrie"

    @pytest.mark.asyncio
    async def test_start_stop(self):
        bridge = LogBridge()
        await bridge.start()
        assert bridge._running
        await bridge.stop()
        assert not bridge._running