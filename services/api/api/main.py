from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from api.routers import cves, health, images
from echo_common.config import get_settings
from echo_common.db import create_engine
from echo_common.db.repositories import ImageCVERepository, ImageRepository
from echo_common.logging import configure_logging


def create_app(engine: AsyncEngine | None = None) -> FastAPI:
    """Build the API. Without `engine` the lifespan creates one from settings (and disposes it at shutdown)."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[dict[str, Any]]:
        settings = get_settings()
        configure_logging(settings.log_level, service="api")
        db_engine = engine or create_engine(settings)
        # Lifespan state: available in every request as request.state.<key>.
        yield {
            "engine": db_engine,
            "image_repository": ImageRepository(db_engine),
            "image_cve_repository": ImageCVERepository(db_engine),
        }
        if engine is None:
            await db_engine.dispose()

    app = FastAPI(
        title="Echo Container Security Scanner API",
        description="Query CVEs found by scanning container images with Trivy.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(images.router)
    app.include_router(cves.router)
    return app


app = create_app()
