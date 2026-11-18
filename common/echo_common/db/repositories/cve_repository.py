from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import cves
from echo_common.models import CVE


class CVERepository(BaseRepository[CVE]):
    table = cves
    model = CVE

    async def upsert_many(self, items: list[CVE]) -> None:
        """Insert CVEs, refreshing the details of ones that already exist."""
        await self.insert_many(
            items,
            conflict_on=["id"],
            update=["severity", "title", "description", "primary_url", "source"],
        )
