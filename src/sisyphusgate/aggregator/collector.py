from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class EventCollector:
    def __init__(self, queue_size: int = 10000):
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self._consumers: list[Callable] = []
        self._running = False
        self._consumer_tasks: list[asyncio.Task] = []
        self._total_events = 0

    @property
    def total_events(self) -> int:
        return self._total_events

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    def add_consumer(self, consumer: Callable) -> None:
        self._consumers.append(consumer)

    async def publish(self, event: dict[str, Any]) -> None:
        try:
            await self._queue.put(event)
            self._total_events += 1
        except asyncio.QueueFull:
            logger.warning("event_queue_full", size=self._queue.maxsize)

    async def start(self) -> None:
        self._running = True
        self._consumer_tasks = [
            asyncio.create_task(self._consume_loop(consumer))
            for consumer in self._consumers
        ]
        logger.info("event_collector_started", consumers=len(self._consumers))

    async def stop(self) -> None:
        self._running = False
        try:
            await asyncio.wait_for(self._queue.join(), timeout=5.0)
        except asyncio.TimeoutError:
            pass
        for task in self._consumer_tasks:
            task.cancel()
        await asyncio.gather(*self._consumer_tasks, return_exceptions=True)
        logger.info("event_collector_stopped", total_events=self._total_events)

    async def _consume_loop(self, consumer: Callable) -> None:
        while self._running or not self._queue.empty():
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                try:
                    await consumer(event)
                except Exception:
                    logger.exception("event_consumer_error")
                finally:
                    self._queue.task_done()
            except asyncio.TimeoutError:
                if not self._running and self._queue.empty():
                    break
                continue
            except asyncio.CancelledError:
                break