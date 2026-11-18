"""Scheduler entry point: python -m scheduler"""

import asyncio
import signal

from echo_common.config import get_settings
from echo_common.db import create_engine
from echo_common.logging import configure_logging
from scheduler.publisher import ScanPublisher
from scheduler.runner import ScanScheduler


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, service="scheduler")
    engine = create_engine(settings)
    scheduler = ScanScheduler(
        publisher=ScanPublisher(engine, settings.scan_queue),
        rabbitmq_url=settings.rabbitmq_url,
        interval_seconds=settings.scan_interval_seconds,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    try:
        await scheduler.run(stop)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
