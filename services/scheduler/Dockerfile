# Scheduler image. Build from the repo root (needs ../../common): docker build -f services/scheduler/Dockerfile .

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN pip install --no-cache-dir "poetry==2.5.1"

WORKDIR /app
COPY common/ common/
COPY services/scheduler/pyproject.toml services/scheduler/poetry.lock services/scheduler/

WORKDIR /app/services/scheduler
# Dependencies first so code changes don't invalidate this layer.
RUN poetry install --only main --no-root
COPY services/scheduler/scheduler/ scheduler/
RUN poetry install --only main

RUN useradd --create-home --uid 1000 scheduler
USER scheduler

CMD ["python", "-m", "scheduler"]