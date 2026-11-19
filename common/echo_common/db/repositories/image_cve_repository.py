from sqlalchemy import ColumnElement, delete, func, select

from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import cves, image_cves, images, packages
from echo_common.enums import Severity
from echo_common.models import FindingDetail, ImageCVE


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

    async def find_details(self, *where: ColumnElement[bool]) -> list[FindingDetail]:
        """Findings joined with their image, CVE and package; most severe first."""
        stmt = (
            select(
                image_cves.c.image_id,
                images.c.name.label("image_name"),
                images.c.tag.label("image_tag"),
                image_cves.c.cve_id,
                cves.c.title.label("cve_title"),
                cves.c.description.label("cve_description"),
                cves.c.primary_url.label("cve_primary_url"),
                packages.c.name.label("package_name"),
                packages.c.type.label("package_type"),
                image_cves.c.installed_version,
                image_cves.c.fixed_version,
                image_cves.c.severity,
            )
            .select_from(image_cves.join(images).join(cves).join(packages))
            .where(*where)
            .order_by(image_cves.c.severity.desc(), image_cves.c.cve_id, packages.c.name)
        )
        async with self.engine.connect() as conn:
            return [FindingDetail.model_validate(dict(row._mapping)) for row in await conn.execute(stmt)]

    async def count_cves_by_severity(self) -> dict[int, dict[Severity, int]]:
        """Distinct CVEs per image and severity: {image_id: {severity: count}}."""
        stmt = select(
            image_cves.c.image_id, image_cves.c.severity, func.count(image_cves.c.cve_id.distinct())
        ).group_by(image_cves.c.image_id, image_cves.c.severity)
        counts: dict[int, dict[Severity, int]] = {}
        async with self.engine.connect() as conn:
            for image_id, severity, count in await conn.execute(stmt):
                counts.setdefault(image_id, {})[Severity(severity)] = count
        return counts
