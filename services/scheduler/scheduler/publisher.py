import logging

import aio_pika
from aio_pika.abc import AbstractChannel
from sqlalchemy.ext.asyncio import AsyncEngine

from echo_common.db.repositories import ImageRepository
from echo_common.messaging import ScanRequest, declare_scan_queue
from echo_common.models import ImageRef

logger = logging.getLogger(__name__)


class ScanPublisher:
    """Publishes one scan request per image in the `images` table."""

    def __init__(self, engine: AsyncEngine, queue_name: str) -> None:
        self.queue_name = queue_name
        self.images = ImageRepository(engine)

    async def publish_all(self, channel: AbstractChannel) -> int:
        """Enqueue a scan of every image; returns how many requests were published."""
        await declare_scan_queue(channel, self.queue_name)
        images = await self.images.list_all()
        for image in images:
            request = ScanRequest(image_id=image.id, image=ImageRef(name=image.name, tag=image.tag))
            await channel.default_exchange.publish(
                aio_pika.Message(
                    request.model_dump_json().encode(),
                    content_type="application/json",
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,  # survives a RabbitMQ restart
                ),
                routing_key=self.queue_name,
            )
        logger.info("Published %d scan requests to %r", len(images), self.queue_name)
        return len(images)
