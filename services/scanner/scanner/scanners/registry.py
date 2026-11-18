from echo_common.enums import ScannerType
from scanner.scanners.base import BaseScanner
from scanner.scanners.trivy import TrivyScanner

# To add a scanner (e.g. Grype): add it to ScannerType, subclass BaseScanner, and register it here.
SCANNERS: dict[ScannerType, type[BaseScanner]] = {
    ScannerType.TRIVY: TrivyScanner,
}


def get_scanner(scanner_type: ScannerType, timeout_seconds: int = 600) -> BaseScanner:
    """Build the scanner a worker was started with (`--scanner`)."""
    return SCANNERS[scanner_type](timeout_seconds=timeout_seconds)
