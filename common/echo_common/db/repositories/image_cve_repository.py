from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import image_cves
from echo_common.models import ImageCVE


class ImageCVERepository(BaseRepository[ImageCVE]):
    table = image_cves
    model = ImageCVE

    async def list_for_image(self, image_id: int) -> list[ImageCVE]:
        return await self.find_where(image_cves.c.image_id == image_id)

    async def replace_for_image(self, image_id: int, items: list[ImageCVE]) -> None:
        """Replace an image's findings with the latest scan's (call inside the scan's transaction).

        Duplicate findings are dropped by the uq_image_cve_package constraint.
        """
        await self.delete_where(image_cves.c.image_id == image_id)
        await self.upsert_many(items, conflict_on=["image_id", "cve_id", "package_id", "installed_version"])
