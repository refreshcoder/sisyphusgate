from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class PortConfig(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = "raw"


class GatewayConfig(BaseModel):
    bind_address: str = "0.0.0.0"
    ports: list[PortConfig] = []
    max_connections: int = 10000
    connection_timeout: int = 300


class FrequencyConfig(BaseModel):
    window_seconds: int = 60
    threshold: int = 10


class ThreatThresholds(BaseModel):
    low: int = 0
    medium: int = 30
    high: int = 60
    critical: int = 85


class AnalyzerConfig(BaseModel):
    enable_signatures: bool = True
    enable_frequency: bool = True
    enable_heuristics: bool = True
    frequency: FrequencyConfig = FrequencyConfig()
    threat_thresholds: ThreatThresholds = ThreatThresholds()


class RouteCondition(BaseModel):
    type: str
    value: str | int | float | list[str]


class RouteRule(BaseModel):
    name: str
    priority: int = 0
    conditions: list[RouteCondition] = []
    action: str
    target: Optional[str] = None


class RouterConfig(BaseModel):
    rules: list[RouteRule] = []
    ip_blacklist: list[str] = []
    ip_whitelist: list[str] = []


class SSHConfig(BaseModel):
    enabled: bool = True
    host_key_path: str = "data/ssh_host_key"
    banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    filesystem_path: str = "config/ssh_filesystem.json"


class TelnetConfig(BaseModel):
    enabled: bool = True
    banner: str = "Ubuntu 22.04.3 LTS\\nlocalhost login: "


class HTTPConfig(BaseModel):
    enabled: bool = True
    server_header: str = "Apache/2.4.57 (Ubuntu)"
    templates_path: str = "config/http_templates/"


class TarpitConfig(BaseModel):
    enabled: bool = True
    delay_ms: int = 10000
    max_line_length: int = 64
    max_clients: int = 4096
    protocol: str = "ssh"


class HoneypotConfig(BaseModel):
    ssh: SSHConfig = SSHConfig()
    telnet: TelnetConfig = TelnetConfig()
    http: HTTPConfig = HTTPConfig()
    tarpit: TarpitConfig = TarpitConfig()


class CowrieExternalConfig(BaseModel):
    enabled: bool = False
    mode: str = "docker"
    host: str = "127.0.0.1"
    ssh_port: int = 2222
    telnet_port: int = 2223
    docker_image: str = "cowrie/cowrie:latest"
    config_path: str = "config/cowrie/"
    log_path: str = "logs/cowrie/cowrie.json"


class EndlesshExternalConfig(BaseModel):
    enabled: bool = False
    mode: str = "docker"
    host: str = "127.0.0.1"
    internal_port: int = 2222
    docker_image: str = "shizunge/endlessh-go:latest"
    delay_ms: int = 10000
    max_clients: int = 4096


class SnareExternalConfig(BaseModel):
    enabled: bool = False
    mode: str = "docker"
    host: str = "127.0.0.1"
    internal_port: int = 8080
    docker_image: str = "mushorg/snare:latest"
    tanner_host: str = "http://tanner:8090"


class ExternalHoneypotConfig(BaseModel):
    cowrie: CowrieExternalConfig = CowrieExternalConfig()
    endlessh: EndlesshExternalConfig = EndlesshExternalConfig()
    snare: SnareExternalConfig = SnareExternalConfig()


class AggregatorConfig(BaseModel):
    storage_backend: str = "jsonl"
    jsonl_path: str = "logs/"
    sqlite_path: str = "data/sisyphusgate.db"
    geoip_db_path: str = "data/GeoLite2-City.mmdb"
    event_queue_size: int = 10000
    flush_interval: int = 5


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"
    output: str = "logs/sisyphusgate.log"


class SisyphusConfig(BaseModel):
    gateway: GatewayConfig = GatewayConfig()
    analyzer: AnalyzerConfig = AnalyzerConfig()
    router: RouterConfig = RouterConfig()
    honeypots: HoneypotConfig = HoneypotConfig()
    external_honeypots: ExternalHoneypotConfig = ExternalHoneypotConfig()
    aggregator: AggregatorConfig = AggregatorConfig()
    logging: LoggingConfig = LoggingConfig()


class AppConfig(BaseModel):
    sisyphusgate: SisyphusConfig = SisyphusConfig()


def load_config(config_path: str | None = None) -> AppConfig:
    if config_path is None:
        config_path = os.environ.get(
            "SISYPHUSGATE_CONFIG",
            str(Path(__file__).parent.parent.parent / "config" / "default.yaml"),
        )

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f)

    config = AppConfig.model_validate(raw)

    env_overrides = {
        "SISYPHUSGATE_LOG_LEVEL": ("sisyphusgate.logging.level", str),
        "SISYPHUSGATE_BIND_ADDRESS": ("sisyphusgate.gateway.bind_address", str),
        "SISYPHUSGATE_GEOIP_DB": ("sisyphusgate.aggregator.geoip_db_path", str),
    }

    for env_var, (config_path_str, converter) in env_overrides.items():
        value = os.environ.get(env_var)
        if value:
            parts = config_path_str.split(".")
            target = config
            for part in parts[:-1]:
                target = getattr(target, part)
            setattr(target, parts[-1], converter(value))

    return config