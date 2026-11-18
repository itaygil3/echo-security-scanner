import asyncio
import contextlib
import logging

import aio_pika

from scheduler.publisher import ScanPublisher

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Publishes a scan of every image on startup and then every `interval_seconds`."""

    def __init__(self, publisher: ScanPublisher, rabbitmq_url: str, interval_seconds: float) -> None:
        self.publisher = publisher
        self.rabbitmq_url = rabbitmq_url
        self.interval_seconds = interval_seconds

    async def run(self, stop: asyncio.Event) -> None:
        connection = await aio_pika.connect_robust(self.rabbitmq_url)
        async with connection:
            await self.schedule(await connection.channel(), stop)
        logger.info("Scheduler stopped")

    async def schedule(self, channel: aio_pika.abc.AbstractChannel, stop: asyncio.Event) -> None:
        """Run a round now and then every `interval_seconds` until `stop` is set."""
        logger.info("Scheduling scans every %ss", self.interval_seconds)
        while not stop.is_set():
            await self.run_cycle(channel)
            await self._sleep(stop)

    async def run_cycle(self, channel: aio_pika.abc.AbstractChannel) -> None:
        """One scheduling round; a failure is logged and retried on the next round."""
        try:
            await self.publisher.publish_all(channel)
        except Exception:
            logger.exception("Scheduling round failed; retrying in %ss", self.interval_seconds)

    async def _sleep(self, stop: asyncio.Event) -> None:
        """Wait for the next round, waking up immediately when `stop` is set."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=self.interval_seconds)
