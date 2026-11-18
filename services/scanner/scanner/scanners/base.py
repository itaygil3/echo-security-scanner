import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import ClassVar

from echo_common.enums import ScannerType
from echo_common.models import ImageRef
from scanner.models import Finding, ScanResult
from scanner.scanners.errors import ScannerTimeoutError

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Generic async vulnerability scanner.

    Subclasses set `name` and implement the coroutine `_scan`; `scan` adds the timeout, timing,
    logging and wraps the findings in a scanner-independent `ScanResult`.
    Expected failures must be raised as `ScannerError` subclasses.
    Tool-specific settings (binaries, caches, credentials) belong to the tool's own environment,
    not to the scanner interface. Duplicate findings are resolved by the database.
    """

    name: ClassVar[ScannerType]

    def __init__(self, timeout_seconds: int = 600) -> None:
        self.timeout_seconds = timeout_seconds

    async def scan(self, image: ImageRef) -> ScanResult:
        logger.info("Scanning %s with %s", image, self.name)
        started = time.monotonic()
        try:
            findings = await asyncio.wait_for(self._scan(image), timeout=self.timeout_seconds)
        except TimeoutError as exc:
            raise ScannerTimeoutError(f"{self.name} timed out after {self.timeout_seconds}s scanning {image}") from exc
        logger.info(
            "Scanned %s in %.1fs: %d findings, %d unique CVEs",
            image,
            time.monotonic() - started,
            len(findings),
            len({f.cve.id for f in findings}),
        )
        return ScanResult(image=image, scanner=self.name, findings=findings)

    @abstractmethod
    async def _scan(self, image: ImageRef) -> list[Finding]:
        """Run the underlying tool and return the findings for one image.

        Must release its resources (e.g. kill subprocesses) when cancelled by the timeout.
        """
