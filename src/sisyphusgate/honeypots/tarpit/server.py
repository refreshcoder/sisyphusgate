from __future__ import annotations

import asyncio
import os
from typing import Any

from sisyphusgate.config import TarpitConfig
from sisyphusgate.gateway.session import Session, SessionState
from sisyphusgate.honeypots.base import BaseHoneypot
from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class TarpitHoneypot(BaseHoneypot):
    protocol_name = "tarpit"

    def __init__(self, config: TarpitConfig):
        super().__init__()
        self._config = config
        self._active_clients = 0
        self._total_trapped = 0
        self._lock = asyncio.Lock()

    @property
    def active_clients(self) -> int:
        return self._active_clients

    @property
    def total_trapped(self) -> int:
        return self._total_trapped

    async def start(self) -> None:
        logger.info("tarpit_started", delay_ms=self._config.delay_ms, max_clients=self._config.max_clients)

    async def stop(self) -> None:
        logger.info("tarpit_stopped")

    async def handle_session(self, session: Session, reader: Any, writer: Any) -> None:
        async with self._lock:
            if self._active_clients >= self._config.max_clients:
                writer.close()
                return
            self._active_clients += 1
            self._total_trapped += 1

        logger.info(
            "tarpit_trapped",
            session_id=session.session_id,
            remote=session.remote_host,
            active=self._active_clients,
        )

        self.emit_event("tarpit_enter", session, {"active_clients": self._active_clients})

        try:
            await self._slow_response(writer)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:
            logger.exception("tarpit_error", session_id=session.session_id)
        finally:
            async with self._lock:
                self._active_clients -= 1

            session.state = SessionState.CLOSED
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            self.emit_event("tarpit_exit", session, {
                "active_clients": self._active_clients,
                "duration": session.duration,
            })

    async def _slow_response(self, writer: Any) -> None:
        delay = self._config.delay_ms / 1000.0

        while True:
            chunk = os.urandom(32 + (os.urandom(1)[0] % 128))
            try:
                writer.write(chunk)
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                break

            await asyncio.sleep(delay)