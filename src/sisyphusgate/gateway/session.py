from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto


class SessionState(Enum):
    CONNECTED = auto()
    ANALYZING = auto()
    ROUTED = auto()
    CLOSED = auto()


@dataclass
class Session:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    remote_host: str = ""
    remote_port: int = 0
    local_port: int = 0
    connected_at: float = field(default_factory=time.time)
    bytes_received: int = 0
    bytes_sent: int = 0
    state: SessionState = SessionState.CONNECTED
    protocol: str = "raw"
    initial_data: bytes = b""
    threat_score: int = 0
    threat_level: str = "low"
    route_target: str = ""

    @property
    def remote_addr(self) -> tuple[str, int]:
        return (self.remote_host, self.remote_port)

    @property
    def duration(self) -> float:
        return time.time() - self.connected_at

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "local_port": self.local_port,
            "connected_at": self.connected_at,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "state": self.state.name,
            "protocol": self.protocol,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "route_target": self.route_target,
        }