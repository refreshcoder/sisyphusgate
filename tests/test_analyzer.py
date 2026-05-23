from __future__ import annotations

import pytest

from sisyphusgate.analyzer.engine import AnalysisEngine, AnalysisResult
from sisyphusgate.analyzer.frequency import FrequencyTracker
from sisyphusgate.analyzer.heuristics import analyze_heuristics
from sisyphusgate.analyzer.signatures import DEFAULT_SIGNATURES, Signature
from sisyphusgate.config import AnalyzerConfig
from sisyphusgate.gateway.session import Session


class TestFrequencyTracker:
    def test_basic_recording(self):
        ft = FrequencyTracker(window_seconds=60, threshold=3)
        assert ft.record("1.2.3.4") == 1
        assert ft.record("1.2.3.4") == 2
        assert ft.get_count("1.2.3.4") == 2

    def test_high_frequency(self):
        ft = FrequencyTracker(window_seconds=60, threshold=3)
        for _ in range(3):
            ft.record("10.0.0.1")
        assert ft.is_high_frequency("10.0.0.1")

    def test_below_threshold(self):
        ft = FrequencyTracker(window_seconds=60, threshold=5)
        for _ in range(4):
            ft.record("10.0.0.2")
        assert not ft.is_high_frequency("10.0.0.2")
        assert ft.get_count("10.0.0.2") == 4

    def test_frequency_score(self):
        ft = FrequencyTracker(window_seconds=60, threshold=5)
        for _ in range(6):
            ft.record("10.0.0.3")
        score = ft.get_frequency_score("10.0.0.3")
        assert score >= 50

    def test_top_ips(self):
        ft = FrequencyTracker(window_seconds=60, threshold=3)
        ft.record("10.0.0.1")
        ft.record("10.0.0.1")
        ft.record("10.0.0.2")
        ft.record("10.0.0.2")
        ft.record("10.0.0.2")

        top = ft.get_top_ips(2)
        assert len(top) == 2
        assert top[0][0] == "10.0.0.2"
        assert top[0][1] == 3

    def test_no_data(self):
        ft = FrequencyTracker()
        assert ft.get_count("1.2.3.4") == 0
        assert not ft.is_high_frequency("1.2.3.4")


class TestSignatures:
    def test_ssh_signature_match(self):
        sig = DEFAULT_SIGNATURES[0]
        assert sig.matches(b"SSH-2.0-OpenSSH_8.9")

    def test_http_admin_scan_match(self):
        sig = Signature(
            name="test",
            protocol="http",
            pattern=r"(GET|POST)\s+/(admin|wp-admin)",
            score=40,
        )
        assert sig.matches(b"GET /admin HTTP/1.1")
        assert sig.matches(b"POST /wp-admin/login HTTP/1.1")
        assert not sig.matches(b"GET /index HTTP/1.1")

    def test_sql_injection_match(self):
        sig = Signature(
            name="test_sqli",
            protocol="http",
            pattern=r"\bUNION\s+SELECT\b",
            score=70,
        )
        assert sig.matches(b"GET /?id=1 UNION SELECT password FROM users HTTP/1.1")
        assert not sig.matches(b"GET /?id=1 HTTP/1.1")

    def test_non_matching_protocol(self):
        sig = Signature(
            name="test",
            protocol="http",
            pattern=r"GET",
            score=10,
        )
        assert not sig.matches(b"SSH-2.0-test")


class TestHeuristics:
    def test_empty_payload_port_scan(self):
        session = Session(remote_host="10.0.0.1", remote_port=12345, local_port=22, initial_data=b"")
        score, tags = analyze_heuristics(session)
        assert "port_scan_probe" in tags
        assert score > 0

    def test_large_payload(self):
        session = Session(remote_host="10.0.0.1", remote_port=12345, local_port=22, initial_data=b"A" * 3000)
        score, tags = analyze_heuristics(session)
        assert "large_payload" in tags

    def test_normal_payload(self):
        session = Session(remote_host="10.0.0.1", remote_port=12345, local_port=22, initial_data=b"GET / HTTP/1.1")
        score, tags = analyze_heuristics(session)
        assert "port_scan_probe" not in tags
        assert "large_payload" not in tags


class TestAnalysisEngine:
    @pytest.mark.asyncio
    async def test_analyze_ssh_session(self):
        config = AnalyzerConfig()
        engine = AnalysisEngine(config)

        session = Session(
            remote_host="10.0.0.1",
            remote_port=12345,
            local_port=22,
            initial_data=b"SSH-2.0-OpenSSH_8.9",
            protocol="ssh",
        )

        result = await engine.analyze(session)
        assert isinstance(result, AnalysisResult)
        assert result.protocol == "ssh"
        assert result.score >= 0
        assert result.threat_level in ("low", "medium", "high", "critical")

    @pytest.mark.asyncio
    async def test_analyze_malicious_http(self):
        config = AnalyzerConfig()
        engine = AnalysisEngine(config)

        session = Session(
            remote_host="10.0.0.2",
            remote_port=12346,
            local_port=80,
            initial_data=b"GET /admin/config.php HTTP/1.1\r\nUser-Agent: sqlmap/1.0\r\n\r\n",
            protocol="http",
        )

        result = await engine.analyze(session)
        assert result.score > 0