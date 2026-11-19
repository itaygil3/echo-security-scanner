# API image. Build from the repo root (needs ../../common): docker build -f services/api/Dockerfile .

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN pip install --no-cache-dir "poetry==2.5.1"

WORKDIR /app
COPY common/ common/
COPY services/api/pyproject.toml services/api/poetry.lock services/api/

WORKDIR /app/services/api
# Dependencies first so code changes don't invalidate this layer.
RUN poetry install --only main --no-root
COPY services/api/api/ api/
RUN poetry install --only main

RUN useradd --create-home --uid 1000 api
USER api

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]