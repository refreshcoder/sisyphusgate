from __future__ import annotations

from sisyphusgate.honeypots.base import BaseHoneypot
from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class HoneypotRegistry:
    def __init__(self):
        self._honeypots: dict[str, BaseHoneypot] = {}

    def register(self, name: str, honeypot: BaseHoneypot) -> None:
        self._honeypots[name] = honeypot
        logger.info("honeypot_registered", name=name, protocol=honeypot.protocol_name)

    def unregister(self, name: str) -> None:
        if name in self._honeypots:
            del self._honeypots[name]
            logger.info("honeypot_unregistered", name=name)

    def get(self, name: str) -> BaseHoneypot | None:
        return self._honeypots.get(name)

    def get_by_protocol(self, protocol: str) -> list[BaseHoneypot]:
        return [h for h in self._honeypots.values() if h.protocol_name == protocol]

    def list_all(self) -> list[str]:
        return list(self._honeypots.keys())

    def set_event_callback(self, callback) -> None:
        for honeypot in self._honeypots.values():
            honeypot.set_event_callback(callback)