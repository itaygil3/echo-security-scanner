from sqlalchemy import delete

from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import image_cves
from echo_common.models import ImageCVE


class ImageCVERepository(BaseRepository[ImageCVE]):
    table = image_cves
    model = ImageCVE

    async def list_for_image(self, image_id: int) -> list[ImageCVE]:
        return await self.find_where(image_cves.c.image_id == image_id)

    async def replace_for_image(self, image_id: int, items: list[ImageCVE]) -> None:
        """Replace an image's findings with the latest scan's, atomically.

        Delete + insert run in one transaction, so a failed insert never leaves the image without its
        previous findings. Duplicate findings are dropped by the uq_image_cve_package constraint.
        """
        stmt, rows = self._upsert_statement(
            items, conflict_on=["image_id", "cve_id", "package_id", "installed_version"], update=()
        )
        async with self.engine.begin() as conn:
            await conn.execute(delete(image_cves).where(image_cves.c.image_id == image_id))
            if rows:
                await conn.execute(stmt, rows)
