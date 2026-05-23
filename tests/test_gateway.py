from __future__ import annotations

import pytest

from sisyphusgate.gateway.protocol import Protocol, detect_protocol


class TestProtocolDetection:
    def test_detect_ssh(self):
        result = detect_protocol(b"SSH-2.0-OpenSSH_8.9")
        assert result == Protocol.SSH

    def test_detect_http_get(self):
        result = detect_protocol(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert result == Protocol.HTTP

    def test_detect_http_post(self):
        result = detect_protocol(b"POST /login HTTP/1.1")
        assert result == Protocol.HTTP

    def test_detect_tls(self):
        result = detect_protocol(bytes([0x16, 0x03, 0x01, 0x00, 0x50]))
        assert result == Protocol.TLS

    def test_detect_telnet(self):
        result = detect_protocol(bytes([0xFF, 0xFB, 0x01]))
        assert result == Protocol.TELNET

    def test_detect_raw_empty(self):
        result = detect_protocol(b"")
        assert result == Protocol.RAW

    def test_detect_raw_unknown(self):
        result = detect_protocol(b"\x00\x01\x02\x03")
        assert result == Protocol.RAW

    def test_protocol_from_name(self):
        assert Protocol.from_name("ssh") == Protocol.SSH
        assert Protocol.from_name("http") == Protocol.HTTP
        assert Protocol.from_name("telnet") == Protocol.TELNET
        assert Protocol.from_name("unknown") == Protocol.RAW

    def test_protocol_name(self):
        assert Protocol.SSH.label == "ssh"
        assert Protocol.HTTP.label == "http"