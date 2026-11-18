from datetime import UTC, datetime

from pydantic import Field

from echo_common.models import DomainModel, ImageRef


class ScanRequest(DomainModel):
    """Message on the scan queue: one image to scan (published by the scheduler, consumed by scanners)."""

    image_id: int
    image: ImageRef
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
