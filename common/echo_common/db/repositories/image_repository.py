from typing import Any

from sqlalchemy import func

from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import images
from echo_common.enums import ScanStatus
from echo_common.models import Image, ImageRef

# Statuses that end a scan and therefore update `last_scan_at`.
_FINISHED = {ScanStatus.SUCCESS, ScanStatus.FAILED}


class ImageRepository(BaseRepository[Image]):
    table = images
    model = Image

    async def get_by_ref(self, ref: ImageRef) -> Image | None:
        rows = await self.find_where(images.c.name == ref.name, images.c.tag == ref.tag)
        return rows[0] if rows else None

    async def set_status(self, image_id: int, status: ScanStatus, error: str | None = None) -> None:
        """Move an image to `status`; finishing a scan (SUCCESS/FAILED) also stamps `last_scan_at`."""
        values: dict[str, Any] = {"scan_status": status, "last_error": error, "updated_at": func.now()}
        if status in _FINISHED:
            values["last_scan_at"] = func.now()
        await self.update_where(values, images.c.id == image_id)
