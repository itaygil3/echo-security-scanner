import asyncio

import aio_pika

from echo_common.db.repositories import ImageRepository
from echo_common.enums import ScanStatus
from echo_common.messaging import ScanRequest
from scheduler.publisher import ScanPublisher
from scheduler.runner import ScanScheduler

QUEUE = "scan_requests"


class FakeExchange:
    def __init__(self):
        self.published: list[tuple[aio_pika.Message, str]] = []

    async def publish(self, message, routing_key):
        self.published.append((message, routing_key))


class FakeChannel:
    """Records published messages and declared queues instead of talking to RabbitMQ."""

    def __init__(self):
        self.default_exchange = FakeExchange()
        self.declared: list[str] = []

    async def declare_queue(self, name, **_kwargs):
        self.declared.append(name)


class CountingPublisher:
    def __init__(self, stop_after: int, fail: bool = False):
        self.calls, self.stop_after, self.fail = 0, stop_after, fail
        self.stop = asyncio.Event()

    async def publish_all(self, channel):
        self.calls += 1
        if self.calls >= self.stop_after:
            self.stop.set()
        if self.fail:
            raise RuntimeError("database unavailable")
        return 0


async def test_publish_all_enqueues_every_image(engine):
    channel = FakeChannel()

    published = await ScanPublisher(engine, QUEUE).publish_all(channel)

    images = {i.id: i for i in await ImageRepository(engine).list_all()}
    requests = [ScanRequest.model_validate_json(msg.body) for msg, _ in channel.default_exchange.published]
    assert published == len(images) == 10
    assert {r.image_id for r in requests} == set(images)
    assert all(str(r.image) == str(images[r.image_id]) for r in requests)
    assert {key for _, key in channel.default_exchange.published} == {QUEUE}
    assert all(msg.delivery_mode == aio_pika.DeliveryMode.PERSISTENT for msg, _ in channel.default_exchange.published)
    assert channel.declared == [f"{QUEUE}.dlq", QUEUE]  # queue declared before publishing


async def test_publish_all_skips_images_being_scanned(engine):
    repository = ImageRepository(engine)
    images = await repository.list_all()
    scanning, finished = images[0], images[1]
    await repository.set_status(scanning.id, ScanStatus.SCANNING)
    await repository.set_status(finished.id, ScanStatus.FAILED, error="boom")
    channel = FakeChannel()

    published = await ScanPublisher(engine, QUEUE).publish_all(channel)

    requested = {ScanRequest.model_validate_json(msg.body).image_id for msg, _ in channel.default_exchange.published}
    assert published == len(requested) == 9
    assert scanning.id not in requested
    assert finished.id in requested  # PENDING, SUCCESS and FAILED images are all queued


async def test_schedule_runs_immediately_and_on_interval():
    publisher = CountingPublisher(stop_after=3)
    scheduler = ScanScheduler(publisher, rabbitmq_url="amqp://unused", interval_seconds=0.05)

    await asyncio.wait_for(scheduler.schedule(FakeChannel(), publisher.stop), timeout=2)

    assert publisher.calls == 3


async def test_failed_round_does_not_stop_the_scheduler():
    publisher = CountingPublisher(stop_after=2, fail=True)
    scheduler = ScanScheduler(publisher, rabbitmq_url="amqp://unused", interval_seconds=0.05)

    await asyncio.wait_for(scheduler.schedule(FakeChannel(), publisher.stop), timeout=2)

    assert publisher.calls == 2


async def test_stop_interrupts_the_interval_sleep():
    publisher = CountingPublisher(stop_after=1)
    scheduler = ScanScheduler(publisher, rabbitmq_url="amqp://unused", interval_seconds=3600)

    # One round, then the hour-long wait ends right away because stop is set.
    await asyncio.wait_for(scheduler.schedule(FakeChannel(), publisher.stop), timeout=2)

    assert publisher.calls == 1
