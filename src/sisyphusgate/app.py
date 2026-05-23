from __future__ import annotations

import asyncio
from typing import Any

from sisyphusgate.aggregator.collector import EventCollector
from sisyphusgate.aggregator.geoip import GeoIPResolver
from sisyphusgate.aggregator.reporter import Reporter
from sisyphusgate.aggregator.storage import JSONLStorage, SQLiteStorage, StorageBackend
from sisyphusgate.analyzer.engine import AnalysisEngine
from sisyphusgate.config import (
    AppConfig,
    load_config,
)
from sisyphusgate.gateway.server import GatewayServer
from sisyphusgate.gateway.session import Session
from sisyphusgate.honeypots.external.log_bridge import LogBridge
from sisyphusgate.honeypots.external.manager import ExternalHoneypotManager
from sisyphusgate.honeypots.registry import HoneypotRegistry
from sisyphusgate.honeypots.tarpit.server import TarpitHoneypot
from sisyphusgate.router.dispatcher import HoneypotRouter
from sisyphusgate.router.rules import ActionType
from sisyphusgate.utils.logging import get_logger, setup_logging

logger = get_logger(__name__)

EXTERNAL_HONEYPOT_PORT_MAP: dict[str, tuple[str, int]] = {}


class SisyphusGate:
    def __init__(self, config_path: str | None = None):
        self._config: AppConfig = load_config(config_path)

        log_cfg = self._config.sisyphusgate.logging
        setup_logging(level=log_cfg.level, log_format=log_cfg.format, output=log_cfg.output)

        gateway_cfg = self._config.sisyphusgate.gateway
        self._gateway = GatewayServer(gateway_cfg)

        analyzer_cfg = self._config.sisyphusgate.analyzer
        self._analyzer = AnalysisEngine(analyzer_cfg)

        router_cfg = self._config.sisyphusgate.router
        self._router = HoneypotRouter(router_cfg)

        self._registry = HoneypotRegistry()
        self._setup_honeypots()

        self._ext_manager = ExternalHoneypotManager()

        agg_cfg = self._config.sisyphusgate.aggregator
        self._collector = EventCollector(queue_size=agg_cfg.event_queue_size)
        self._geoip = GeoIPResolver(db_path=agg_cfg.geoip_db_path)
        self._reporter = Reporter(self._collector, self._geoip)

        self._storage = self._create_storage(agg_cfg)
        self._collector.add_consumer(self._store_event)

        self._registry.set_event_callback(self._on_honeypot_event)

        self._log_bridge = LogBridge(publish_callback=self._on_honeypot_event)
        self._setup_log_bridge_sources()

        self._setup_external_port_map()

        self._gateway.set_connection_handler(self._handle_connection)

        self._running = False

    def _setup_external_port_map(self) -> None:
        ext = self._config.sisyphusgate.external_honeypots

        EXTERNAL_HONEYPOT_PORT_MAP.clear()

        if ext.cowrie.enabled:
            EXTERNAL_HONEYPOT_PORT_MAP["cowrie_ssh"] = (ext.cowrie.host, ext.cowrie.ssh_port)
            EXTERNAL_HONEYPOT_PORT_MAP["cowrie_telnet"] = (ext.cowrie.host, ext.cowrie.telnet_port)
            EXTERNAL_HONEYPOT_PORT_MAP["cowrie"] = (ext.cowrie.host, ext.cowrie.ssh_port)

        if ext.endlessh.enabled:
            EXTERNAL_HONEYPOT_PORT_MAP["endlessh"] = (ext.endlessh.host, ext.endlessh.internal_port)

        if ext.snare.enabled:
            EXTERNAL_HONEYPOT_PORT_MAP["snare"] = (ext.snare.host, ext.snare.internal_port)

    def _setup_log_bridge_sources(self) -> None:
        ext = self._config.sisyphusgate.external_honeypots
        if ext.cowrie.enabled:
            self._log_bridge.add_log_source("cowrie", ext.cowrie.log_path)

    def _setup_honeypots(self) -> None:
        h_config = self._config.sisyphusgate.honeypots

        if h_config.tarpit.enabled:
            self._registry.register("tarpit", TarpitHoneypot(h_config.tarpit))

    def _create_storage(self, agg_cfg) -> StorageBackend:
        if agg_cfg.storage_backend == "sqlite":
            return SQLiteStorage(agg_cfg.sqlite_path, agg_cfg.flush_interval)
        return JSONLStorage(agg_cfg.jsonl_path, agg_cfg.flush_interval)

    async def _on_honeypot_event(self, event: dict[str, Any]) -> None:
        country, city, lat, lng = self._geoip.resolve(event.get("source_ip", ""))
        event["source_country"] = country
        event["source_city"] = city
        event["source_latitude"] = lat
        event["source_longitude"] = lng
        await self._collector.publish(event)

    async def _store_event(self, event: dict[str, Any]) -> None:
        await self._storage.write(event)

    async def _handle_connection(self, session: Session, reader, writer, port_config) -> None:
        analysis = await self._analyzer.analyze(session)

        decision = await self._router.route(
            analysis,
            session.remote_host,
            port_config.port,
        )

        session.route_target = decision.target

        if decision.action == ActionType.BLOCK:
            logger.info("connection_blocked", session_id=session.session_id, ip=session.remote_host)
            return

        if decision.action == ActionType.LOG_ONLY:
            logger.info("connection_logged_only", session_id=session.session_id, ip=session.remote_host)
            return

        if decision.action == ActionType.ROUTE_TO_EXTERNAL:
            target = decision.target
            port_entry = EXTERNAL_HONEYPOT_PORT_MAP.get(target)
            if port_entry is None:
                logger.warning("external_target_not_found", target=target, session_id=session.session_id)
                return
            host, port = port_entry
            logger.info(
                "routing_to_external",
                session_id=session.session_id,
                ip=session.remote_host,
                target=target,
                endpoint=f"{host}:{port}",
            )
            await self._gateway.proxy_to(session, reader, writer, host, port)
            return

        if decision.action == ActionType.ROUTE_TO_TARPIT:
            honeypot = self._registry.get("tarpit")
            if honeypot:
                await honeypot.handle_session(session, reader, writer)
            return

        honeypot = self._registry.get(decision.target or session.protocol)
        if honeypot is None:
            logger.info("no_honeypot_found", target=decision.target, ip=session.remote_host)
            return

        await honeypot.handle_session(session, reader, writer)

    async def start(self) -> None:
        self._running = True
        logger.info("sisyphusgate_starting", version="0.2.0")

        ext = self._config.sisyphusgate.external_honeypots

        await self._ext_manager.start_all(
            cowrie_config=ext.cowrie if ext.cowrie.enabled else None,
            endlessh_config=ext.endlessh if ext.endlessh.enabled else None,
            snare_config=ext.snare if ext.snare.enabled else None,
        )

        await self._geoip.start()
        await self._collector.start()
        await self._log_bridge.start()

        for honeypot in self._registry._honeypots.values():
            await honeypot.start()

        await self._gateway.start()

        logger.info("sisyphusgate_started")

    async def run(self) -> None:
        await self.start()
        while self._running:
            await asyncio.sleep(1)

    async def stop(self) -> None:
        self._running = False
        logger.info("sisyphusgate_stopping")

        await self._gateway.stop()

        for honeypot in self._registry._honeypots.values():
            await honeypot.stop()

        await self._log_bridge.stop()
        await self._collector.stop()
        await self._storage.flush()
        await self._storage.close()
        await self._geoip.stop()
        await self._ext_manager.stop_all()

        logger.info("sisyphusgate_stopped")

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "gateway": {
                "active_sessions": self._gateway.active_sessions,
                "total_sessions": self._gateway.total_sessions,
            },
            "collector": {
                "total_events": self._collector.total_events,
                "queue_size": self._collector.queue_size,
            },
            "honeypots": self._registry.list_all(),
            "external_honeypots": {
                "cowrie": self._config.sisyphusgate.external_honeypots.cowrie.enabled,
                "endlessh": self._config.sisyphusgate.external_honeypots.endlessh.enabled,
                "snare": self._config.sisyphusgate.external_honeypots.snare.enabled,
            },
        }