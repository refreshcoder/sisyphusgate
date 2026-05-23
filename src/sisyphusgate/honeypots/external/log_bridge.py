from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Callable

from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)

COWRIE_EVENT_MAP = {
    "cowrie.login.success": "auth_success",
    "cowrie.login.failed": "auth_failed",
    "cowrie.session.connect": "connection",
    "cowrie.session.closed": "disconnect",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command_failed",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.client.version": "client_info",
    "cowrie.client.size": "client_info",
    "cowrie.client.kex": "client_info",
    "cowrie.direct-tcpip.request": "tunnel_request",
    "cowrie.direct-tcpip.data": "tunnel_data",
}


class LogBridge:
    def __init__(self, publish_callback: Callable | None = None):
        self._publish = publish_callback
        self._watchers: list[asyncio.Task] = []
        self._running = False
        self._log_paths: list[tuple[str, str]] = []
        self._file_positions: dict[str, int] = {}

    def add_log_source(self, name: str, path: str) -> None:
        self._log_paths.append((name, path))
        self._file_positions[path] = 0

    def set_publish_callback(self, callback: Callable) -> None:
        self._publish = callback

    async def start(self) -> None:
        self._running = True
        for name, path in self._log_paths:
            self._file_positions[path] = self._get_file_size(path)
            task = asyncio.create_task(self._watch_log(name, path))
            self._watchers.append(task)
        logger.info("log_bridge_started", sources=len(self._log_paths))

    async def stop(self) -> None:
        self._running = False
        for task in self._watchers:
            task.cancel()
        await asyncio.gather(*self._watchers, return_exceptions=True)
        self._watchers.clear()
        logger.info("log_bridge_stopped")

    async def _watch_log(self, name: str, path: str) -> None:
        while self._running:
            try:
                new_events = await self._read_new_lines(path)
                for line in new_events:
                    await self._process_line(name, line)
            except Exception:
                logger.exception("log_bridge_error", source=name, path=path)
            await asyncio.sleep(1.0)

    async def _read_new_lines(self, path: str) -> list[str]:
        if not os.path.exists(path):
            return []

        current_size = self._get_file_size(path)
        last_pos = self._file_positions.get(path, 0)

        if current_size < last_pos:
            last_pos = 0

        if current_size == last_pos:
            return []

        with open(path, "r") as f:
            f.seek(last_pos)
            data = f.read(current_size - last_pos)
            self._file_positions[path] = current_size

        lines = data.strip().split("\n")
        return [ln for ln in lines if ln.strip()]

    async def _process_line(self, source: str, line: str) -> None:
        if not self._publish:
            return

        if source == "cowrie":
            await self._process_cowrie_line(line)
        elif source == "endlessh":
            await self._process_endlessh_line(line)

    async def _process_cowrie_line(self, line: str) -> None:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return

        eventid = raw.get("eventid", "")
        event_type = COWRIE_EVENT_MAP.get(eventid, "unknown")

        event = {
            "timestamp": raw.get("timestamp", time.time()),
            "event_type": event_type,
            "source_ip": raw.get("src_ip", ""),
            "source_port": raw.get("src_port", 0),
            "destination_port": raw.get("dst_port", 0),
            "protocol": "ssh",
            "honeypot_type": "cowrie",
            "session_id": raw.get("session", ""),
            "data": raw,
        }

        await self._publish(event)

    async def _process_endlessh_line(self, line: str) -> None:
        import re

        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        ip = match.group(1) if match else ""

        event = {
            "timestamp": time.time(),
            "event_type": "tarpit",
            "source_ip": ip,
            "source_port": 0,
            "destination_port": 0,
            "protocol": "ssh",
            "honeypot_type": "endlessh",
            "session_id": "",
            "data": {"raw": line},
        }

        await self._publish(event)

    @staticmethod
    def _get_file_size(path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0