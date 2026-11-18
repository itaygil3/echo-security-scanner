import asyncio

import pytest

from echo_common.db.repositories import CVERepository, ImageCVERepository, ImageRepository
from echo_common.enums import ScannerType, ScanStatus, Severity
from echo_common.messaging import ScanRequest
from echo_common.models import CVE, ImageRef, Package
from scanner.models import Finding
from scanner.scanners import BaseScanner, ImageNotFoundError
from scanner.worker import ScanWorker


def _finding(cve_id: str, package: str, version: str = "1.0", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        cve=CVE(id=cve_id, severity=severity, source=ScannerType.TRIVY),
        package=Package(name=package, type="debian"),
        installed_version=version,
        fixed_version="2.0",
    )


class FakeScanner(BaseScanner):
    name = ScannerType.TRIVY

    def __init__(self, findings=None, error=None, delay=0.0):
        super().__init__(timeout_seconds=5)
        self.findings, self.error, self.delay = findings or [], error, delay
        self.running = self.max_running = 0

    async def _scan(self, image):
        self.running += 1
        self.max_running = max(self.max_running, self.running)
        try:
            await asyncio.sleep(self.delay)
            if self.error:
                raise self.error
            return self.findings
        finally:
            self.running -= 1


def _worker(engine, scanner, concurrency=1) -> ScanWorker:
    return ScanWorker(scanner, engine, rabbitmq_url="amqp://unused", queue_name="unused", concurrency=concurrency)


async def _request(engine, ref: str) -> ScanRequest:
    image = await ImageRepository(engine).get_by_ref(ImageRef.parse(ref))
    return ScanRequest(image_id=image.id, image=ImageRef(name=image.name, tag=image.tag))


async def test_successful_scan_is_stored(engine):
    findings = [
        _finding("CVE-2021-3711", "openssl", severity=Severity.CRITICAL),
        _finding("CVE-2021-3711", "libssl1.1", severity=Severity.CRITICAL),  # same CVE, other package
        _finding("CVE-2022-1304", "e2fsprogs"),
        _finding("CVE-2022-1304", "e2fsprogs"),  # duplicate finding, dropped by the DB
    ]
    request = await _request(engine, "nginx:1.19")

    await _worker(engine, FakeScanner(findings)).process(request)

    image = await ImageRepository(engine).get(request.image_id)
    stored = await ImageCVERepository(engine).list_for_image(request.image_id)
    cves = {c.id: c for c in await CVERepository(engine).list_all()}
    assert image.scan_status is ScanStatus.SUCCESS and image.last_scan_at is not None and image.last_error is None
    assert sorted(f.cve_id for f in stored) == ["CVE-2021-3711", "CVE-2021-3711", "CVE-2022-1304"]
    assert cves["CVE-2021-3711"].severity is Severity.CRITICAL


async def test_rescan_replaces_previous_findings(engine):
    request = await _request(engine, "redis:6.0")
    await _worker(engine, FakeScanner([_finding("CVE-2021-3711", "openssl")])).process(request)
    await _worker(engine, FakeScanner([_finding("CVE-2022-1304", "e2fsprogs")])).process(request)

    stored = await ImageCVERepository(engine).list_for_image(request.image_id)
    assert [f.cve_id for f in stored] == ["CVE-2022-1304"]


async def test_scanner_error_marks_image_failed(engine):
    request = await _request(engine, "httpd:2.4")

    await _worker(engine, FakeScanner(error=ImageNotFoundError("Image httpd:2.4 not found"))).process(request)

    image = await ImageRepository(engine).get(request.image_id)
    assert image.scan_status is ScanStatus.FAILED
    assert image.last_error == "Image httpd:2.4 not found"
    assert image.last_scan_at is not None


async def test_unknown_image_is_skipped(engine):
    scanner = FakeScanner()
    await _worker(engine, scanner).process(ScanRequest(image_id=999_999, image=ImageRef.parse("ghost:1")))
    assert scanner.max_running == 0


async def test_semaphore_limits_concurrent_scans(engine):
    scanner = FakeScanner(delay=0.2)
    worker = _worker(engine, scanner, concurrency=2)
    requests = [await _request(engine, ref) for ref in ("nginx:1.19", "redis:6.0", "httpd:2.4", "alpine:3.12")]

    await asyncio.gather(*(worker.process(r) for r in requests))

    assert scanner.max_running == 2
    statuses = {
        i.scan_status for i in await ImageRepository(engine).list_all() if i.id in {r.image_id for r in requests}
    }
    assert statuses == {ScanStatus.SUCCESS}


class FakeMessage:
    """Stand-in for an aio-pika incoming message: records how it was settled."""

    def __init__(self, body: bytes):
        self.body = body
        self.settled: str | None = None

    async def ack(self):
        self.settled = "ack"

    async def reject(self, requeue: bool = False):
        self.settled = f"reject(requeue={requeue})"


async def test_done_message_is_acked(engine):
    request = await _request(engine, "nginx:1.19")
    message = FakeMessage(request.model_dump_json().encode())

    await _worker(engine, FakeScanner([_finding("CVE-2021-3711", "openssl")])).process_message(message)

    assert message.settled == "ack"


async def test_failed_scan_message_is_acked(engine):
    request = await _request(engine, "httpd:2.4")
    message = FakeMessage(request.model_dump_json().encode())

    await _worker(engine, FakeScanner(error=ImageNotFoundError("not found"))).process_message(message)

    assert message.settled == "ack"  # handled: image marked FAILED, message removed


async def test_invalid_message_is_dead_lettered(engine):
    message = FakeMessage(b"garbage")
    await _worker(engine, FakeScanner()).process_message(message)
    assert message.settled == "reject(requeue=False)"


async def test_unexpected_error_is_dead_lettered(engine):
    request = await _request(engine, "redis:6.0")
    message = FakeMessage(request.model_dump_json().encode())

    await _worker(engine, FakeScanner(error=RuntimeError("bug"))).process_message(message)

    assert message.settled == "reject(requeue=False)"


async def test_cancelled_scan_is_not_settled(engine):
    request = await _request(engine, "alpine:3.12")
    message = FakeMessage(request.model_dump_json().encode())
    task = asyncio.create_task(_worker(engine, FakeScanner(delay=10)).process_message(message))
    await asyncio.sleep(0.2)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert message.settled is None  # RabbitMQ requeues it when the connection closes
