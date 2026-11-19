from datetime import datetime

from pydantic import BaseModel, Field

from echo_common.enums import ScanStatus


class ImageSummary(BaseModel):
    """A scanned image with its number of distinct CVEs per severity."""

    name: str
    tag: str
    scan_status: ScanStatus
    last_scan_at: datetime | None
    last_error: str | None
    severity_counts: dict[str, int] = Field(
        examples=[{"CRITICAL": 11, "HIGH": 96, "MEDIUM": 167, "LOW": 83, "UNKNOWN": 5, "total": 362}]
    )
