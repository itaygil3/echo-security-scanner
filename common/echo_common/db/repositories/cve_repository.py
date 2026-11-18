from collections.abc import Iterable, Sequence

from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import cves
from echo_common.models import CVE

# Details refreshed when a known CVE is reported again.
_DETAIL_COLUMNS = ("severity", "title", "description", "primary_url", "source")


class CVERepository(BaseRepository[CVE]):
    table = cves
    model = CVE

    async def upsert_many(
        self,
        items: Iterable[CVE],
        *,
        conflict_on: Sequence[str] | None = ("id",),
        update: Sequence[str] = _DETAIL_COLUMNS,
    ) -> None:
        """Insert CVEs, refreshing the details of ones that already exist (by default)."""
        await super().upsert_many(items, conflict_on=conflict_on, update=update)
