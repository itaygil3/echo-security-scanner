from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy import ColumnElement, Insert, Row, Table, delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncEngine

from echo_common.models import DomainModel


class BaseRepository[ModelT: DomainModel]:
    """Repository for one table: generic queries that map rows to the table's Pydantic model.

    Subclasses set `table` and `model`. Create once per process with the engine; every method
    runs its query directly on the engine (writes in their own transaction).
    """

    table: Table
    model: type[ModelT]

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine

    # --- reads -------------------------------------------------------------------------------

    async def get(self, id_: Any) -> ModelT | None:
        rows = await self.find_where(self.table.c.id == id_)
        return rows[0] if rows else None

    async def list_all(self) -> list[ModelT]:
        return await self.find_where()

    async def find_where(self, *where: ColumnElement[bool]) -> list[ModelT]:
        async with self.engine.connect() as conn:
            result = await conn.execute(select(self.table).where(*where).order_by(self.table.c.id))
            return [self._to_model(row) for row in result]

    # --- writes ------------------------------------------------------------------------------

    async def upsert_many(
        self,
        items: Iterable[ModelT],
        *,
        conflict_on: Sequence[str] | None = None,
        update: Sequence[str] = (),
    ) -> None:
        """Bulk insert.

        conflict_on=None           plain INSERT (a conflict raises)
        conflict_on=[...]          ON CONFLICT (...) DO NOTHING  - duplicates are dropped by the DB
        conflict_on + update=[...] ON CONFLICT (...) DO UPDATE   - upsert of the given columns
        """
        stmt, rows = self._upsert_statement(items, conflict_on=conflict_on, update=update)
        if not rows:
            return
        async with self.engine.begin() as conn:
            await conn.execute(stmt, rows)

    async def update_where(self, values: Mapping[str, Any], *where: ColumnElement[bool]) -> int:
        """UPDATE matching rows; returns the number of rows updated."""
        async with self.engine.begin() as conn:
            result = await conn.execute(update(self.table).where(*where).values(**values))
            return result.rowcount

    async def delete_where(self, *where: ColumnElement[bool]) -> int:
        """DELETE matching rows; returns the number of rows deleted."""
        async with self.engine.begin() as conn:
            result = await conn.execute(delete(self.table).where(*where))
            return result.rowcount

    # --- helpers -----------------------------------------------------------------------------

    def _upsert_statement(
        self,
        items: Iterable[ModelT],
        *,
        conflict_on: Sequence[str] | None,
        update: Sequence[str],
    ) -> tuple[Insert, list[dict[str, Any]]]:
        """Build the INSERT ... ON CONFLICT statement and its rows (for upsert_many and composed writes)."""
        rows = [self._to_row(item) for item in items]
        stmt = insert(self.table)
        if conflict_on and update:
            # Postgres can't update the same row twice in one statement: keep the last row per key.
            rows = list({tuple(row[col] for col in conflict_on): row for row in rows}.values())
            stmt = stmt.on_conflict_do_update(
                index_elements=list(conflict_on),
                set_={col: stmt.excluded[col] for col in update},
            )
        elif conflict_on:
            stmt = stmt.on_conflict_do_nothing(index_elements=list(conflict_on))
        return stmt, rows

    def _to_model(self, row: Row) -> ModelT:
        return self.model.model_validate(dict(row._mapping))

    def _to_row(self, item: ModelT) -> dict[str, Any]:
        """Model -> column values. Unset ids and server-defaulted columns are left to the database."""
        data = item.model_dump()
        row = {}
        for column in self.table.columns:
            if column.name not in data:
                continue
            value = data[column.name]
            if value is None and (column.primary_key or column.server_default is not None):
                continue
            row[column.name] = value
        return row
