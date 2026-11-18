from collections import Counter
from datetime import UTC, datetime

from pydantic import Field

from echo_common.enums import ScannerType, Severity
from echo_common.models import DomainModel, ImageRef
from scanner.models.finding import Finding


class ScanResult(DomainModel):
    """Output of one successful scan, independent of which scanner produced it."""

    image: ImageRef
    scanner: ScannerType
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    findings: list[Finding] = Field(default_factory=list)

    def severity_counts(self) -> dict[Severity, int]:
        """Unique CVEs per severity (a CVE found in several packages is counted once)."""
        unique = {f.cve.id: f.severity for f in self.findings}
        counts = Counter(unique.values())
        return {severity: counts.get(severity, 0) for severity in Severity}
