from __future__ import annotations

from enum import Enum, auto


class Protocol(Enum):
    SSH = auto()
    HTTP = auto()
    TLS = auto()
    TELNET = auto()
    RAW = auto()

    @classmethod
    def from_name(cls, name: str) -> "Protocol":
        mapping = {
            "ssh": cls.SSH,
            "http": cls.HTTP,
            "tls": cls.TLS,
            "telnet": cls.TELNET,
            "raw": cls.RAW,
        }
        return mapping.get(name.lower(), cls.RAW)

    @property
    def label(self) -> str:
        return self._name_.lower()


SSH_SIGNATURE = b"SSH-"
HTTP_METHODS = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT "]
TLS_CLIENT_HELLO = bytes([0x16, 0x03])
TELNET_IAC = bytes([0xFF])


def detect_protocol(data: bytes) -> Protocol:
    if not data:
        return Protocol.RAW

    if data.startswith(SSH_SIGNATURE):
        return Protocol.SSH

    if data.startswith(TLS_CLIENT_HELLO):
        return Protocol.TLS

    if data.startswith(TELNET_IAC):
        return Protocol.TELNET

    for method in HTTP_METHODS:
        if data.startswith(method):
            return Protocol.HTTP

    return Protocol.RAW