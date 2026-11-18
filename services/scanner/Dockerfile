# Scanner worker image: Python service + Trivy CLI.
# Build from the repo root (needs ../../common): docker build -f services/scanner/Dockerfile .

ARG TRIVY_VERSION=0.76.1

# Official Trivy image, used only as the source of the trivy binary.
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1 \
    TRIVY_CACHE_DIR=/var/cache/trivy

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN pip install --no-cache-dir "poetry==2.5.1"

WORKDIR /app
COPY common/ common/
COPY services/scanner/pyproject.toml services/scanner/poetry.lock services/scanner/

WORKDIR /app/services/scanner
# Dependencies first so code changes don't invalidate this layer.
RUN poetry install --only main --no-root
COPY services/scanner/scanner/ scanner/
RUN poetry install --only main

# Run as non-root; the Trivy vulnerability DB cache is a volume in docker-compose.
RUN useradd --create-home --uid 1000 scanner \
    && mkdir -p "$TRIVY_CACHE_DIR" \
    && chown scanner "$TRIVY_CACHE_DIR"
USER scanner