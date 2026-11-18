from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy import ColumnElement, Row, Table, delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from echo_common.models import DomainModel


class BaseRepository[ModelT: DomainModel]:
    """Repository for one table: generic queries that map rows to the table's Pydantic model.

    Subclasses set `table` and `model`. The session (and its transaction) is owned by the caller,
    so several repositories can take part in one unit of work.
    """

    table: Table
    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # --- reads -------------------------------------------------------------------------------

    async def get(self, id_: Any) -> ModelT | None:
        rows = await self.find_where(self.table.c.id == id_)
        return rows[0] if rows else None

    async def list_all(self) -> list[ModelT]:
        return await self.find_where()

    async def find_where(self, *where: ColumnElement[bool]) -> list[ModelT]:
        result = await self.session.execute(select(self.table).where(*where).order_by(self.table.c.id))
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
        rows = [self._to_row(item) for item in items]
        if not rows:
            return
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
        await self.session.execute(stmt, rows)

    async def update_where(self, values: Mapping[str, Any], *where: ColumnElement[bool]) -> int:
        """UPDATE matching rows; returns the number of rows updated."""
        result = await self.session.execute(update(self.table).where(*where).values(**values))
        return result.rowcount

    async def delete_where(self, *where: ColumnElement[bool]) -> int:
        """DELETE matching rows; returns the number of rows deleted."""
        result = await self.session.execute(delete(self.table).where(*where))
        return result.rowcount

    # --- mapping -----------------------------------------------------------------------------

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
