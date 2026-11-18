from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from echo_common.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Async engine (connection pool) for one service process; `await engine.dispose()` at shutdown."""
    return create_async_engine(settings.database_url, pool_size=settings.database_pool_size, pool_pre_ping=True)
