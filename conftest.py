import os
from pathlib import Path

import asyncpg
import pytest
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import create_async_engine

INIT_DIR = Path(__file__).resolve().parent / "db" / "init"
TEST_URL = make_url(os.getenv("TEST_DATABASE_URL", "postgresql+asyncpg://echo:echo@localhost:5432/echo_test"))


def _asyncpg_dsn(url: URL, database: str) -> str:
    return url.set(drivername="postgresql", database=database).render_as_string(hide_password=False)


@pytest.fixture
async def engine():
    """A fresh test database built from db/init/*.sql (schema + seed), skipped if Postgres is down."""
    try:
        admin = await asyncpg.connect(_asyncpg_dsn(TEST_URL, "postgres"), timeout=3)
    except (OSError, asyncpg.PostgresError) as exc:
        pytest.skip(f"Postgres not reachable ({exc}); start it with `docker compose up -d postgres`")
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{TEST_URL.database}" WITH (FORCE)')
        await admin.execute(f'CREATE DATABASE "{TEST_URL.database}"')
    finally:
        await admin.close()

    conn = await asyncpg.connect(_asyncpg_dsn(TEST_URL, TEST_URL.database))
    try:
        for script in sorted(INIT_DIR.glob("*.sql")):
            await conn.execute(script.read_text())
    finally:
        await conn.close()

    engine = create_async_engine(TEST_URL.render_as_string(hide_password=False))
    yield engine
    await engine.dispose()
