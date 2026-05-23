from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from sisyphusgate.gateway.session import Session


class BaseHoneypot(ABC):
    protocol_name: str = "raw"

    def __init__(self):
        self._event_callback: Optional[Callable] = None

    def set_event_callback(self, callback: Callable) -> None:
        self._event_callback = callback

    def emit_event(self, event_type: str, session: Session, data: dict[str, Any] | None = None) -> None:
        if self._event_callback:
            event = {
                "timestamp": time.time(),
                "event_type": event_type,
                "source_ip": session.remote_host,
                "source_port": session.remote_port,
                "destination_port": session.local_port,
                "protocol": session.protocol,
                "honeypot_type": self.protocol_name,
                "session_id": session.session_id,
                "threat_level": session.threat_level,
                "data": data or {},
            }
            self._event_callback(event)

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def handle_session(self, session: Session, reader: Any, writer: Any) -> None: ...