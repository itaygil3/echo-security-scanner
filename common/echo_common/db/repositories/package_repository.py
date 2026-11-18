from sqlalchemy import tuple_

from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import packages
from echo_common.models import Package

PackageKey = tuple[str, str]  # (name, type)


class PackageRepository(BaseRepository[Package]):
    table = packages
    model = Package

    async def ensure_many(self, items: list[Package]) -> dict[PackageKey, int]:
        """Insert missing packages (duplicates dropped by the DB) and return their ids by (name, type)."""
        if not items:
            return {}
        await self.upsert_many(items, conflict_on=["name", "type"])
        keys = {(p.name, p.type) for p in items}
        stored = await self.find_where(tuple_(packages.c.name, packages.c.type).in_(keys))
        return {(p.name, p.type): p.id for p in stored}
