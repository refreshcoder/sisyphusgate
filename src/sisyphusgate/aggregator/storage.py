from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class StorageBackend(ABC):
    @abstractmethod
    async def write(self, event: dict[str, Any]) -> None: ...

    @abstractmethod
    async def flush(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...


class JSONLStorage(StorageBackend):
    def __init__(self, output_path: str, flush_interval: int = 5):
        self._output_path = output_path
        self._flush_interval = flush_interval
        self._buffer: list[str] = []
        self._lock = asyncio.Lock()
        self._last_flush = time.time()
        self._current_date = ""

    async def write(self, event: dict[str, Any]) -> None:
        async with self._lock:
            self._buffer.append(json.dumps(event, default=str))
            if time.time() - self._last_flush >= self._flush_interval:
                await self._do_flush()

    async def flush(self) -> None:
        async with self._lock:
            await self._do_flush()

    async def _do_flush(self) -> None:
        if not self._buffer:
            return

        date_str = datetime.now().strftime("%Y-%m-%d")
        os.makedirs(self._output_path, exist_ok=True)
        filepath = os.path.join(self._output_path, f"sisyphusgate-{date_str}.jsonl")

        lines = "\n".join(self._buffer) + "\n"
        with open(filepath, "a") as f:
            f.write(lines)

        count = len(self._buffer)
        self._buffer.clear()
        self._last_flush = time.time()

    async def close(self) -> None:
        await self.flush()


class SQLiteStorage(StorageBackend):
    def __init__(self, db_path: str, flush_interval: int = 5):
        self._db_path = db_path
        self._flush_interval = flush_interval
        self._buffer: list[dict] = []
        self._lock = asyncio.Lock()
        self._last_flush = time.time()
        self._local = threading.local()

        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                source_country TEXT,
                source_city TEXT,
                destination_port INTEGER,
                protocol TEXT,
                honeypot_type TEXT,
                session_id TEXT,
                threat_level TEXT,
                data TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                start_time TEXT NOT NULL,
                end_time TEXT,
                source_ip TEXT,
                source_port INTEGER,
                protocol TEXT,
                honeypot_type TEXT,
                threat_level TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)
        """)
        conn.commit()
        conn.close()

    async def write(self, event: dict[str, Any]) -> None:
        async with self._lock:
            self._buffer.append(event)
            if time.time() - self._last_flush >= self._flush_interval:
                await self._do_flush()

    async def flush(self) -> None:
        async with self._lock:
            await self._do_flush()

    async def _do_flush(self) -> None:
        if not self._buffer:
            return

        conn = self._get_conn()
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        for event in self._buffer:
            event_type = event.get("event_type", "unknown")
            source_ip = event.get("source_ip", "")
            source_port = event.get("source_port", 0)
            source_country = event.get("source_country", "")
            source_city = event.get("source_city", "")
            destination_port = event.get("destination_port", 0)
            protocol = event.get("protocol", "")
            honeypot_type = event.get("honeypot_type", "")
            session_id = event.get("session_id", "")
            threat_level = event.get("threat_level", "")
            data = json.dumps(event.get("data", {}))

            event_ts = event.get("timestamp", time.time())
            if isinstance(event_ts, (int, float)):
                event_ts = datetime.fromtimestamp(event_ts).strftime("%Y-%m-%dT%H:%M:%S")

            conn.execute(
                "INSERT INTO events (timestamp, event_type, source_ip, source_port, source_country, source_city, destination_port, protocol, honeypot_type, session_id, threat_level, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event_ts, event_type, source_ip, source_port, source_country, source_city, destination_port, protocol, honeypot_type, session_id, threat_level, data),
            )

            if event_type == "connection":
                conn.execute(
                    "INSERT OR REPLACE INTO sessions (session_id, start_time, source_ip, source_port, protocol, honeypot_type, threat_level) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (session_id, event_ts, source_ip, source_port, protocol, honeypot_type, threat_level),
                )

        conn.commit()
        self._buffer.clear()
        self._last_flush = time.time()

    async def close(self) -> None:
        await self.flush()