from collections.abc import Iterable

from sqlalchemy import tuple_

from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import packages
from echo_common.models import Package

PackageKey = tuple[str, str]  # (name, type)


class PackageRepository(BaseRepository[Package]):
    table = packages
    model = Package

    async def get_ids(self, items: Iterable[Package]) -> dict[PackageKey, int]:
        """Ids of stored packages by (name, type)."""
        keys = {(p.name, p.type) for p in items}
        if not keys:
            return {}
        stored = await self.find_where(tuple_(packages.c.name, packages.c.type).in_(keys))
        return {(p.name, p.type): p.id for p in stored}
