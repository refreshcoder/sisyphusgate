from __future__ import annotations

import asyncio
import signal
from typing import Callable, Optional

from sisyphusgate.config import GatewayConfig, PortConfig
from sisyphusgate.gateway.protocol import Protocol, detect_protocol
from sisyphusgate.gateway.session import Session, SessionState
from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)

PROXY_BUFFER_SIZE = 65536


class GatewayServer:
    def __init__(self, config: GatewayConfig):
        self._config = config
        self._servers: list[asyncio.AbstractServer] = []
        self._active_sessions: dict[str, Session] = {}
        self._session_count = 0
        self._lock = asyncio.Lock()
        self._running = False
        self._connection_handler: Optional[Callable] = None

    def set_connection_handler(self, handler: Callable) -> None:
        self._connection_handler = handler

    @property
    def active_sessions(self) -> int:
        return len(self._active_sessions)

    @property
    def total_sessions(self) -> int:
        return self._session_count

    async def start(self) -> None:
        self._running = True
        loop = asyncio.get_running_loop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._shutdown(s)))

        for port_config in self._config.ports:
            server = await asyncio.start_server(
                lambda r, w, pc=port_config: self._handle_connection(r, w, pc),
                host=self._config.bind_address,
                port=port_config.port,
            )
            self._servers.append(server)
            logger.info(
                "gateway_listening",
                address=f"{self._config.bind_address}:{port_config.port}",
                protocol=port_config.protocol,
            )

    async def _shutdown(self, sig: signal.Signals) -> None:
        logger.info("gateway_shutdown_initiated", signal=sig.name)
        self._running = False

        for server in self._servers:
            server.close()
        for server in self._servers:
            await server.wait_closed()

        logger.info("gateway_shutdown_complete")

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port_config: PortConfig
    ) -> None:
        peer = writer.get_extra_info("peername")
        if peer is None:
            writer.close()
            return

        async with self._lock:
            self._session_count += 1

        session = Session(
            remote_host=peer[0],
            remote_port=peer[1],
            local_port=port_config.port,
        )

        self._active_sessions[session.session_id] = session

        logger.info(
            "connection_accepted",
            session_id=session.session_id,
            remote=f"{peer[0]}:{peer[1]}",
            port=port_config.port,
            protocol=port_config.protocol,
        )

        try:
            initial_data = await asyncio.wait_for(
                reader.read(4096), timeout=self._config.connection_timeout
            )
            session.bytes_received = len(initial_data)
            session.initial_data = initial_data

            detected = detect_protocol(initial_data)
            session.protocol = detected.label

            if self._connection_handler:
                await self._connection_handler(session, reader, writer, port_config)
            else:
                writer.close()

        except asyncio.TimeoutError:
            logger.info("connection_timeout", session_id=session.session_id, remote=peer[0])
        except ConnectionResetError:
            logger.info("connection_reset", session_id=session.session_id, remote=peer[0])
        except Exception:
            logger.exception("connection_error", session_id=session.session_id, remote=peer[0])
        finally:
            session.state = SessionState.CLOSED
            self._active_sessions.pop(session.session_id, None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self) -> None:
        if self._running:
            await self._shutdown(signal.SIGTERM)

    async def proxy_to(self, session: Session, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter, target_host: str, target_port: int) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(target_host, target_port)
        except (ConnectionRefusedError, OSError) as e:
            logger.warning("proxy_connection_failed", target=f"{target_host}:{target_port}", error=str(e))
            return

        logger.info("proxy_established", session_id=session.session_id,
                     target=f"{target_host}:{target_port}")

        if session.initial_data:
            upstream_writer.write(session.initial_data)
            await upstream_writer.drain()

        async def relay(src: asyncio.StreamReader, dst: asyncio.StreamWriter, direction: str) -> None:
            try:
                while True:
                    data = await src.read(PROXY_BUFFER_SIZE)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
                    if direction == "downstream":
                        session.bytes_received += len(data)
                    else:
                        session.bytes_sent += len(data)
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    dst.close()
                    await dst.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(
            relay(reader, upstream_writer, "downstream"),
            relay(upstream_reader, writer, "upstream"),
        )

        try:
            upstream_writer.close()
            await upstream_writer.wait_closed()
        except Exception:
            pass