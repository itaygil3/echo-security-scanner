"""End-to-end: publish a scan request to RabbitMQ and verify what the real scanner stored in Postgres.

Needs the compose stack (postgres, rabbitmq, scanner):
    docker compose up -d --build
    poetry run pytest -m e2e
"""

import asyncio
import os
from datetime import UTC, datetime

import aio_pika
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from echo_common.db.repositories import CVERepository, ImageCVERepository, ImageRepository, PackageRepository
from echo_common.db.tables import images
from echo_common.enums import ScannerType, ScanStatus, Severity
from echo_common.messaging import ScanRequest, declare_scan_queue
from echo_common.models import Image, ImageRef

pytestmark = pytest.mark.e2e

DATABASE_URL = os.getenv("E2E_DATABASE_URL", "postgresql+asyncpg://echo:echo@localhost:5432/echo")
RABBITMQ_URL = os.getenv("E2E_RABBITMQ_URL", "amqp://echo:echo@localhost:5672/%2F")
SCAN_QUEUE = os.getenv("SCAN_QUEUE", "scan_requests")
SCAN_TIMEOUT_SECONDS = 300


@pytest.fixture
async def stack_engine():
    engine = create_async_engine(DATABASE_URL)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except OSError as exc:
        await engine.dispose()
        pytest.skip(f"compose stack not running ({exc}); start it with `docker compose up -d --build`")
    yield engine
    await engine.dispose()


async def _publish(image: Image) -> None:
    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    async with connection:
        channel = await connection.channel()
        await declare_scan_queue(channel, SCAN_QUEUE)
        request = ScanRequest(image_id=image.id, image=ImageRef(name=image.name, tag=image.tag))
        await channel.default_exchange.publish(
            aio_pika.Message(request.model_dump_json().encode(), delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
            routing_key=SCAN_QUEUE,
        )


async def _wait_for_scan(repo: ImageRepository, image_id: int, published_at: datetime) -> Image:
    """Poll until the scanner finished this request (a scan that ended after we published it)."""
    deadline = asyncio.get_running_loop().time() + SCAN_TIMEOUT_SECONDS
    while asyncio.get_running_loop().time() < deadline:
        image = await repo.get(image_id)
        finished = image.scan_status in (ScanStatus.SUCCESS, ScanStatus.FAILED)
        if finished and image.last_scan_at and image.last_scan_at >= published_at:
            return image
        await asyncio.sleep(2)
    pytest.fail(f"scan of image {image_id} did not finish within {SCAN_TIMEOUT_SECONDS}s (is the scanner running?)")


async def test_scan_stores_findings_in_db(stack_engine):
    images_repo = ImageRepository(stack_engine)
    image = await images_repo.get_by_ref(ImageRef.parse("alpine:3.12"))
    assert image is not None, "alpine:3.12 should be seeded"

    published_at = datetime.now(UTC)
    await _publish(image)
    scanned = await _wait_for_scan(images_repo, image.id, published_at)

    assert scanned.scan_status is ScanStatus.SUCCESS
    assert scanned.last_error is None

    findings = await ImageCVERepository(stack_engine).list_for_image(image.id)
    assert findings, "alpine:3.12 is end-of-life and has known CVEs"
    cves, packages = CVERepository(stack_engine), PackageRepository(stack_engine)
    for finding in findings:
        cve = await cves.get(finding.cve_id)
        package = await packages.get(finding.package_id)
        assert cve.id.startswith("CVE-")
        assert cve.source is ScannerType.TRIVY
        assert finding.severity in Severity
        assert package.type == "alpine"
        assert finding.installed_version
        assert finding.detected_at >= published_at


async def test_scan_of_missing_image_marks_it_failed(stack_engine):
    images_repo = ImageRepository(stack_engine)
    ref = ImageRef.parse("nginx:e2e-does-not-exist")
    await images_repo.upsert_many([Image(name=ref.name, tag=ref.tag)], conflict_on=["name", "tag"])
    image = await images_repo.get_by_ref(ref)
    try:
        published_at = datetime.now(UTC)
        await _publish(image)
        scanned = await _wait_for_scan(images_repo, image.id, published_at)

        assert scanned.scan_status is ScanStatus.FAILED
        assert "not found" in scanned.last_error
        assert await ImageCVERepository(stack_engine).list_for_image(image.id) == []
    finally:
        await images_repo.delete_where(images.c.id == image.id)
