from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum, auto

from sisyphusgate.analyzer.engine import AnalysisResult


class ActionType(Enum):
    ROUTE_TO_HONEYPOT = auto()
    ROUTE_TO_TARPIT = auto()
    ROUTE_TO_EXTERNAL = auto()
    BLOCK = auto()
    LOG_ONLY = auto()

    @classmethod
    def from_str(cls, value: str) -> "ActionType":
        mapping = {
            "route_to_honeypot": cls.ROUTE_TO_HONEYPOT,
            "route_to_tarpit": cls.ROUTE_TO_TARPIT,
            "route_to_external": cls.ROUTE_TO_EXTERNAL,
            "block": cls.BLOCK,
            "log_only": cls.LOG_ONLY,
        }
        return mapping.get(value, cls.LOG_ONLY)


@dataclass
class RouteDecision:
    action: ActionType
    target: str = ""
    matched_rule: str = ""


@dataclass
class RouteRule:
    name: str
    priority: int = 0
    conditions: list[RouteCondition] = field(default_factory=list)
    action: str = "log_only"
    target: str = ""


@dataclass
class RouteCondition:
    type: str
    value: str | int | float | list[str]


def evaluate_condition(condition: RouteCondition, result: AnalysisResult, remote_ip: str, blacklist: list[str], whitelist: list[str]) -> bool:
    if condition.type == "protocol_match":
        return result.protocol == condition.value

    if condition.type == "score_threshold":
        return result.score >= int(condition.value)

    if condition.type == "frequency_threshold":
        if result.is_high_frequency:
            return True
        return result.frequency_count >= int(condition.value)

    if condition.type == "tag_match":
        if isinstance(condition.value, list):
            return any(tag in result.tags for tag in condition.value)
        return condition.value in result.tags

    if condition.type == "ip_match":
        if condition.value == "blacklist":
            return remote_ip in blacklist or _ip_in_cidr_list(remote_ip, blacklist)
        if condition.value == "whitelist":
            return remote_ip in whitelist
        return _ip_matches(remote_ip, str(condition.value))

    if condition.type == "port_match":
        return str(condition.value) == str(getattr(result, "local_port", ""))

    return False


def _ip_matches(ip: str, pattern: str) -> bool:
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return ip == pattern


def _ip_in_cidr_list(ip: str, cidr_list: list[str]) -> bool:
    for entry in cidr_list:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if ipaddress.ip_address(ip) in network:
                return True
        except ValueError:
            if ip == entry:
                return True
    return False