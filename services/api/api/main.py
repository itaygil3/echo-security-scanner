from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from api.routers import cves, health, images
from echo_common.config import get_settings
from echo_common.db import create_engine
from echo_common.db.repositories import ImageCVERepository, ImageRepository
from echo_common.logging import configure_logging


def _attach(app: FastAPI, engine: AsyncEngine) -> None:
    app.state.engine = engine
    app.state.images = ImageRepository(engine)
    app.state.image_cves = ImageCVERepository(engine)


def create_app(engine: AsyncEngine | None = None) -> FastAPI:
    """Build the API. Without `engine` it creates one from settings at startup (and disposes it at shutdown)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if engine is not None:
            yield
            return
        settings = get_settings()
        configure_logging(settings.log_level, service="api")
        owned = create_engine(settings)
        _attach(app, owned)
        yield
        await owned.dispose()

    app = FastAPI(
        title="Echo Container Security Scanner API",
        description="Query CVEs found by scanning container images with Trivy.",
        version="0.1.0",
        lifespan=lifespan,
    )
    if engine is not None:
        _attach(app, engine)
    app.include_router(health.router)
    app.include_router(images.router)
    app.include_router(cves.router)
    return app


app = create_app()
