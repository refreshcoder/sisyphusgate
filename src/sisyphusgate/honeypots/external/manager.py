from __future__ import annotations

import asyncio
import os
import shutil
import subprocess

from sisyphusgate.config import CowrieExternalConfig, EndlesshExternalConfig, SnareExternalConfig
from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class ExternalHoneypotManager:
    def __init__(self):
        self._processes: dict[str, subprocess.Popen] = {}
        self._running = False
        self._health_targets: dict[str, tuple[str, int]] = {}

    async def start_all(self, cowrie_config: CowrieExternalConfig | None,
                        endlessh_config: EndlesshExternalConfig | None,
                        snare_config: SnareExternalConfig | None) -> None:
        self._running = True

        if cowrie_config and cowrie_config.enabled:
            await self._start_cowrie(cowrie_config)

        if endlessh_config and endlessh_config.enabled:
            await self._start_endlessh(endlessh_config)

        if snare_config and snare_config.enabled:
            await self._start_snare(snare_config)

        logger.info("external_honeypots_started")

    async def stop_all(self) -> None:
        self._running = False
        for name, proc in self._processes.items():
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except Exception:
                pass
            logger.info("external_process_stopped", name=name)
        self._processes.clear()
        logger.info("external_honeypots_stopped")

    async def health_check(self) -> dict[str, bool]:
        results = {}
        for name, (host, port) in list(self._health_targets.items()):
            results[name] = await self._check_port(host, port)
        return results

    async def _start_cowrie(self, config: CowrieExternalConfig) -> None:
        if config.mode == "docker":
            logger.info("cowrie_starting_via_docker", image=config.docker_image)
            self._health_targets["cowrie_ssh"] = ("127.0.0.1", config.ssh_port)
            self._health_targets["cowrie_telnet"] = ("127.0.0.1", config.telnet_port)
        else:
            cowrie_bin = shutil.which("cowrie") or shutil.which("twistd")
            if cowrie_bin:
                proc = subprocess.Popen(
                    [cowrie_bin, "cowrie"],
                    cwd=os.getcwd(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._processes["cowrie"] = proc
                self._health_targets["cowrie_ssh"] = ("127.0.0.1", config.ssh_port)
                logger.info("cowrie_started_via_subprocess", pid=proc.pid)
            else:
                logger.warning("cowrie_not_found", message="Install cowrie via pip or use docker mode")

    async def _start_endlessh(self, config: EndlesshExternalConfig) -> None:
        if config.mode == "docker":
            logger.info("endlessh_starting_via_docker", image=config.docker_image)
            self._health_targets["endlessh"] = ("127.0.0.1", config.internal_port)
        else:
            endlessh_bin = shutil.which("endlessh") or shutil.which("endlessh-go")
            if endlessh_bin:
                proc = subprocess.Popen(
                    [endlessh_bin, "-p", str(config.internal_port),
                     "-d", str(config.delay_ms),
                     "-m", str(config.max_clients)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._processes["endlessh"] = proc
                self._health_targets["endlessh"] = ("127.0.0.1", config.internal_port)
                logger.info("endlessh_started_via_subprocess", pid=proc.pid)
            else:
                logger.warning("endlessh_not_found", message="Install endlessh or use docker mode")

    async def _start_snare(self, config: SnareExternalConfig) -> None:
        if config.mode == "docker":
            logger.info("snare_starting_via_docker", image=config.docker_image)
            self._health_targets["snare"] = ("127.0.0.1", config.internal_port)
        else:
            logger.warning("snare_subprocess_unsupported", message="SNARE is best deployed via Docker")

    async def _check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False