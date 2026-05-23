from __future__ import annotations

import pytest

from sisyphusgate.analyzer.engine import AnalysisResult
from sisyphusgate.config import RouterConfig, RouteRule as ConfigRouteRule, RouteCondition as ConfigRouteCondition
from sisyphusgate.router.dispatcher import HoneypotRouter
from sisyphusgate.router.rate_limiter import RateLimiter
from sisyphusgate.router.rules import ActionType, RouteDecision


class TestRateLimiter:
    def test_allow_basic(self):
        rl = RateLimiter(window_seconds=60, threshold=5, bucket_capacity=10)
        for _ in range(5):
            assert rl.allow("1.2.3.4")

    def test_is_high_frequency(self):
        rl = RateLimiter(window_seconds=60, threshold=3, bucket_capacity=10)
        for _ in range(5):
            rl.allow("10.0.0.1")
        assert rl.is_high_frequency("10.0.0.1")

    def test_not_high_frequency(self):
        rl = RateLimiter(window_seconds=60, threshold=10, bucket_capacity=20)
        for _ in range(3):
            rl.allow("10.0.0.2")
        assert not rl.is_high_frequency("10.0.0.2")


class TestHoneypotRouter:
    def _make_config(self, rules=None):
        return RouterConfig(
            rules=rules or [],
            ip_blacklist=[],
            ip_whitelist=[],
        )

    @pytest.mark.asyncio
    async def test_default_log_only(self):
        config = self._make_config()
        router = HoneypotRouter(config)

        analysis = AnalysisResult(session_id="test", protocol="ssh", score=0)
        decision = await router.route(analysis, "1.2.3.4", 22)
        assert decision.action == ActionType.LOG_ONLY

    @pytest.mark.asyncio
    async def test_whitelist_bypass(self):
        config = RouterConfig(
            rules=[],
            ip_blacklist=[],
            ip_whitelist=["10.0.0.5"],
        )
        router = HoneypotRouter(config)

        analysis = AnalysisResult(session_id="test", protocol="ssh", score=90)
        decision = await router.route(analysis, "10.0.0.5", 22)
        assert decision.action == ActionType.LOG_ONLY

    @pytest.mark.asyncio
    async def test_route_to_honeypot_by_protocol(self):
        config = RouterConfig(
            rules=[
                ConfigRouteRule(
                    name="ssh_malicious",
                    priority=80,
                    conditions=[
                        ConfigRouteCondition(type="protocol_match", value="ssh"),
                        ConfigRouteCondition(type="score_threshold", value=30),
                    ],
                    action="route_to_honeypot",
                    target="ssh",
                ),
            ],
            ip_blacklist=[],
            ip_whitelist=[],
        )
        router = HoneypotRouter(config)

        analysis = AnalysisResult(session_id="test", protocol="ssh", score=60)
        decision = await router.route(analysis, "1.2.3.4", 22)
        assert decision.action == ActionType.ROUTE_TO_HONEYPOT
        assert decision.target == "ssh"

    @pytest.mark.asyncio
    async def test_route_to_tarpit_high_frequency(self):
        config = RouterConfig(
            rules=[
                ConfigRouteRule(
                    name="high_freq_tarpit",
                    priority=100,
                    conditions=[
                        ConfigRouteCondition(type="frequency_threshold", value=3),
                    ],
                    action="route_to_tarpit",
                ),
            ],
            ip_blacklist=[],
            ip_whitelist=[],
        )
        router = HoneypotRouter(config)

        analysis = AnalysisResult(
            session_id="test",
            protocol="ssh",
            score=10,
            is_high_frequency=True,
            frequency_count=10,
        )
        decision = await router.route(analysis, "1.2.3.4", 22)
        assert decision.action == ActionType.ROUTE_TO_TARPIT

    @pytest.mark.asyncio
    async def test_route_to_external(self):
        config = RouterConfig(
            rules=[
                ConfigRouteRule(
                    name="ssh_to_cowrie",
                    priority=85,
                    conditions=[
                        ConfigRouteCondition(type="protocol_match", value="ssh"),
                        ConfigRouteCondition(type="score_threshold", value=30),
                    ],
                    action="route_to_external",
                    target="cowrie",
                ),
            ],
            ip_blacklist=[],
            ip_whitelist=[],
        )
        router = HoneypotRouter(config)

        analysis = AnalysisResult(session_id="test", protocol="ssh", score=60)
        decision = await router.route(analysis, "1.2.3.4", 22)
        assert decision.action == ActionType.ROUTE_TO_EXTERNAL
        assert decision.target == "cowrie"

    @pytest.mark.asyncio
    async def test_route_high_freq_to_external_endlessh(self):
        config = RouterConfig(
            rules=[
                ConfigRouteRule(
                    name="high_freq_to_endlessh",
                    priority=100,
                    conditions=[
                        ConfigRouteCondition(type="protocol_match", value="ssh"),
                        ConfigRouteCondition(type="frequency_threshold", value=5),
                    ],
                    action="route_to_external",
                    target="endlessh",
                ),
            ],
            ip_blacklist=[],
            ip_whitelist=[],
        )
        router = HoneypotRouter(config)

        analysis = AnalysisResult(
            session_id="test",
            protocol="ssh",
            score=20,
            is_high_frequency=True,
            frequency_count=10,
        )
        decision = await router.route(analysis, "1.2.3.4", 22)
        assert decision.action == ActionType.ROUTE_TO_EXTERNAL
        assert decision.target == "endlessh"