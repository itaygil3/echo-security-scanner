from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Self

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from echo_common.config import Settings


class Database:
    """Async SQLAlchemy engine + session factory for one service process.

    Create once at startup, `await dispose()` at shutdown.
    """

    def __init__(self, url: str, pool_size: int = 5) -> None:
        self.engine: AsyncEngine = create_async_engine(url, pool_size=pool_size, pool_pre_ping=True)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        return cls(settings.database_url, pool_size=settings.database_pool_size)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """A session wrapped in a transaction: commits on success, rolls back on error."""
        async with self.sessionmaker() as session, session.begin():
            yield session

    async def dispose(self) -> None:
        await self.engine.dispose()
