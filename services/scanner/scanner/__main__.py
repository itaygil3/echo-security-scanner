"""Scanner worker entry point: python -m scanner --scanner trivy --concurrency 1"""

import argparse
import asyncio
import signal

from echo_common.config import get_settings
from echo_common.db import create_engine
from echo_common.enums import ScannerType
from echo_common.logging import configure_logging
from scanner.scanners import get_scanner
from scanner.worker import ScanWorker


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="scanner", description="Consume scan requests from RabbitMQ and scan images.")
    parser.add_argument("--scanner", type=ScannerType, choices=list(ScannerType), default=ScannerType.TRIVY)
    parser.add_argument("--concurrency", type=_positive_int, default=1, help="max scans running at once")
    parser.add_argument("--timeout", type=_positive_int, default=600, help="per-scan timeout in seconds")
    return parser.parse_args(argv)


async def main(args: argparse.Namespace) -> None:
    settings = get_settings()
    configure_logging(settings.log_level, service="scanner")
    engine = create_engine(settings)
    worker = ScanWorker(
        scanner=get_scanner(args.scanner, timeout_seconds=args.timeout),
        engine=engine,
        rabbitmq_url=settings.rabbitmq_url,
        queue_name=settings.scan_queue,
        concurrency=args.concurrency,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    try:
        await worker.run(stop)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
