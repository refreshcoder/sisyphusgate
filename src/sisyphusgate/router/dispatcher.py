from __future__ import annotations

from sisyphusgate.analyzer.engine import AnalysisResult
from sisyphusgate.config import RouterConfig
from sisyphusgate.router.rate_limiter import RateLimiter
from sisyphusgate.router.rules import (
    ActionType,
    RouteCondition,
    RouteDecision,
    RouteRule,
    evaluate_condition,
)
from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class HoneypotRouter:
    def __init__(self, config: RouterConfig):
        self._config = config
        self._rate_limiter = RateLimiter(
            window_seconds=60,
            threshold=getattr(config, "frequency_threshold", 10),
        )
        self._rules: list[RouteRule] = []

        for rule_config in config.rules:
            conditions = []
            for cond in rule_config.conditions:
                conditions.append(RouteCondition(type=cond.type, value=cond.value))
            rule = RouteRule(
                name=rule_config.name,
                priority=rule_config.priority,
                conditions=conditions,
                action=rule_config.action,
                target=rule_config.target or "",
            )
            self._rules.append(rule)

        self._rules.sort(key=lambda r: r.priority, reverse=True)

    @property
    def rate_limiter(self) -> RateLimiter:
        return self._rate_limiter

    async def route(self, analysis: AnalysisResult, remote_ip: str, local_port: int) -> RouteDecision:
        is_whitelisted = remote_ip in self._config.ip_whitelist
        if is_whitelisted:
            logger.info("router_whitelist_bypass", ip=remote_ip)
            return RouteDecision(action=ActionType.LOG_ONLY, matched_rule="whitelist")

        enhanced_result = analysis
        setattr(enhanced_result, "local_port", local_port)

        for rule in self._rules:
            if not rule.conditions:
                logger.info("router_default_rule", ip=remote_ip, rule=rule.name)
                action = ActionType.from_str(rule.action)
                return RouteDecision(action=action, target=rule.target, matched_rule=rule.name)

            all_match = True
            for condition in rule.conditions:
                if not evaluate_condition(
                    condition,
                    enhanced_result,
                    remote_ip,
                    self._config.ip_blacklist,
                    self._config.ip_whitelist,
                ):
                    all_match = False
                    break

            if all_match:
                action = ActionType.from_str(rule.action)
                logger.info(
                    "router_rule_matched",
                    ip=remote_ip,
                    rule=rule.name,
                    action=action.name,
                    target=rule.target,
                )
                return RouteDecision(action=action, target=rule.target, matched_rule=rule.name)

        logger.info("router_no_match", ip=remote_ip)
        return RouteDecision(action=ActionType.LOG_ONLY, matched_rule="fallback")