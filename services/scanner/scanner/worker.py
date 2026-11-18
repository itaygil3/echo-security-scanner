import asyncio
import logging

import aio_pika
from aio_pika.abc import AbstractIncomingMessage
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncEngine

from echo_common.db.repositories import CVERepository, ImageCVERepository, ImageRepository, PackageRepository
from echo_common.enums import ScanStatus
from echo_common.messaging import ScanRequest, declare_scan_queue
from echo_common.models import Image, ImageCVE
from scanner.models import ScanResult
from scanner.scanners import BaseScanner, ScannerError

logger = logging.getLogger(__name__)

CVE_DETAIL_COLUMNS = ["title", "description", "primary_url", "source"]


class ScanWorker:
    """Consumes scan requests from RabbitMQ and runs each scan as a background task.

    - At most `concurrency` scans run at the same time (semaphore; RabbitMQ prefetch matches it).
    - A message is acked (deleted from the queue) only when its scan task is done.
    - Expected scan failures (ScannerError): image marked FAILED, message acked.
    - Invalid messages and unexpected errors: message rejected to the dead-letter queue.
    """

    def __init__(
        self,
        scanner: BaseScanner,
        engine: AsyncEngine,
        rabbitmq_url: str,
        queue_name: str,
        concurrency: int = 1,
        shutdown_timeout: float = 30,
    ) -> None:
        self.scanner = scanner
        self.rabbitmq_url = rabbitmq_url
        self.queue_name = queue_name
        self.concurrency = concurrency
        self.shutdown_timeout = shutdown_timeout
        self.scan_slots = asyncio.Semaphore(concurrency)
        self.tasks: set[asyncio.Task] = set()
        self.images = ImageRepository(engine)
        self.cves = CVERepository(engine)
        self.packages = PackageRepository(engine)
        self.image_cves = ImageCVERepository(engine)

    async def run(self, stop: asyncio.Event) -> None:
        """Consume until `stop` is set, then let running scans finish (up to `shutdown_timeout`)."""
        connection = await aio_pika.connect_robust(self.rabbitmq_url)
        async with connection:
            channel = await connection.channel()
            await channel.set_qos(prefetch_count=self.concurrency)
            queue = await declare_scan_queue(channel, self.queue_name)
            consumer_tag = await queue.consume(self.handle_message)
            logger.info(
                "Worker consuming %r with %s (concurrency %d)", self.queue_name, self.scanner.name, self.concurrency
            )
            await stop.wait()
            await queue.cancel(consumer_tag)
            await self.drain()

    async def drain(self) -> None:
        """Wait for running scans; cancel the rest (their unacked messages are requeued by RabbitMQ)."""
        if not self.tasks:
            return
        logger.info("Waiting up to %ss for %d running scans", self.shutdown_timeout, len(self.tasks))
        _, pending = await asyncio.wait(self.tasks, timeout=self.shutdown_timeout)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    async def handle_message(self, message: AbstractIncomingMessage) -> None:
        """Consumer callback: start the scan in the background and return right away."""
        task = asyncio.create_task(self.process_message(message))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def process_message(self, message: AbstractIncomingMessage) -> None:
        """Run one scan request and settle its message.

        ack            -> done: RabbitMQ deletes the message from the queue
        reject(False)  -> invalid or unexpected failure: RabbitMQ moves it to the dead-letter queue
        neither        -> cancelled on shutdown: RabbitMQ requeues it when the connection closes
        """
        try:
            request = ScanRequest.model_validate_json(message.body)
        except ValidationError as exc:
            logger.error(
                "Invalid scan request %r (%d errors), sending to dead-letter queue",
                message.body[:200],
                exc.error_count(),
            )
            await message.reject(requeue=False)
            return

        try:
            await self.process(request)
        except Exception:
            logger.exception("Unexpected error processing %s, sending to dead-letter queue", request.image)
            await message.reject(requeue=False)
            return

        await message.ack()

    async def process(self, request: ScanRequest) -> None:
        """Scan one image (once a scan slot is free) and store the outcome on its row."""
        image = await self.images.get(request.image_id)
        if image is None:
            logger.warning("Image id %d (%s) no longer exists; skipping", request.image_id, request.image)
            return

        async with self.scan_slots:
            await self.images.set_status(image.id, ScanStatus.SCANNING)
            try:
                result = await self.scanner.scan(image)
            except ScannerError as exc:
                logger.warning("Scan of %s failed: %s", image, exc)
                await self.images.set_status(image.id, ScanStatus.FAILED, error=str(exc))
                return

        await self.store_result(image, result)

    async def store_result(self, image: Image, result: ScanResult) -> None:
        """Store a successful scan.

        Every step is idempotent and the findings are replaced atomically, so a crash midway is
        repaired by the next scan; SUCCESS is set last.
        """
        await self.cves.upsert_many([f.cve for f in result.findings], conflict_on=["id"], update=CVE_DETAIL_COLUMNS)
        packages = [f.package for f in result.findings]
        await self.packages.upsert_many(packages, conflict_on=["name", "type"])
        package_ids = await self.packages.get_ids(packages)

        await self.image_cves.replace_for_image(
            image.id,
            [
                ImageCVE(
                    image_id=image.id,
                    cve_id=f.cve.id,
                    package_id=package_ids[(f.package.name, f.package.type)],
                    installed_version=f.installed_version,
                    fixed_version=f.fixed_version,
                    severity=f.severity,
                )
                for f in result.findings
            ],
        )
        await self.images.set_status(image.id, ScanStatus.SUCCESS)
        logger.info("Stored %d findings for %s", len(result.findings), image)
