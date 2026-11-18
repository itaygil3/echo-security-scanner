from pydantic import Field

from echo_common.enums import ScannerType, Severity
from echo_common.models.base import CVE_ID_PATTERN, DomainModel


class CVE(DomainModel):
    """Row of `cves`: a unique vulnerability."""

    id: str = Field(pattern=CVE_ID_PATTERN, max_length=64, examples=["CVE-2021-23017"])
    severity: Severity = Severity.UNKNOWN
    title: str | None = None
    description: str | None = None
    primary_url: str | None = None
    source: ScannerType = Field(description="Scanner that reported the CVE")
