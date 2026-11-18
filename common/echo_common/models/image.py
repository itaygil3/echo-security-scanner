from datetime import datetime

from echo_common.enums import ScanStatus
from echo_common.models.image_ref import ImageRef


class Image(ImageRef):
    """Row of `images`: an image to scan and the state of its last scan."""

    id: int | None = None
    last_scan_at: datetime | None = None
    scan_status: ScanStatus = ScanStatus.PENDING
    last_error: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
