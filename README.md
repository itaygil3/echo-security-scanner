# Echo Container Security Scanner

A backend that scans container images for CVEs with [Trivy](https://trivy.dev) every 15 minutes, stores the
results in PostgreSQL and serves them through a REST API.

It's built as small services that talk through RabbitMQ, each with its own Dockerfile, and runs with one
`docker compose up`.

> Original assignment: [echo-ha/echo-security-scanner](https://github.com/echo-ha/echo-security-scanner)

- [Architecture](#architecture)
- [Quick start](#quick-start)
- [End-to-end verification checklist](#end-to-end-verification-checklist)
- [Configuration](#configuration)
- [API](#api)
- [Database schema](#database-schema)
- [How scanning works](#how-scanning-works)
- [Development](#development)
- [Known limitations](#known-limitations)

---

## Architecture

```mermaid
flowchart LR
    scheduler["scheduler<br/>every 15 min"] -- "ScanRequest per image" --> queue[["RabbitMQ<br/>scan_requests"]]
    queue -- consume --> scanner["scanner worker<br/>Trivy CLI"]
    queue -. "rejected" .-> dlq[["scan_requests.dlq"]]
    scanner -- "status + findings" --> db[("PostgreSQL")]
    scheduler -- "read images" --> db
    api["api<br/>FastAPI :8000"] -- "read" --> db
    scanner -- "pull image" --> registry(("Docker Hub"))
```

| Service | Built from | Role |
|---|---|---|
| `postgres` | `db/Dockerfile` (`postgres:16`) | Creates the schema and seeds the 10 images on first start (`db/init/*.sql`) |
| `rabbitmq` | `rabbitmq:3-management` | Durable `scan_requests` queue and its dead-letter queue. UI at http://localhost:15672 (`echo`/`echo`) |
| `scheduler` | `services/scheduler/Dockerfile` | Publishes one scan request per image that isn't `SCANNING`, on startup and every `SCAN_INTERVAL_SECONDS` |
| `scanner` | `services/scanner/Dockerfile` (Python + Trivy 0.76.1) | Consumes requests, runs Trivy, stores the results and each image's scan status |
| `api` | `services/api/Dockerfile` | FastAPI + Pydantic REST API on http://localhost:8000 |

Shared code (config, Pydantic models, async SQLAlchemy repositories, queue setup) lives in the `common/`
package (`echo_common`), which every service installs.

**Tech:** Python 3.12, asyncio throughout, FastAPI, Pydantic v2, SQLAlchemy 2 async (Core) with `asyncpg`,
`aio-pika`, Trivy, PostgreSQL 16, RabbitMQ 3, Poetry, Docker Compose.

## Quick start

**Prerequisites:** Docker with Compose v2. Internet access is needed to pull images and Trivy's vulnerability
DB. For running tests locally you also need Python 3.12+ and [Poetry](https://python-poetry.org) 2.x.

```bash
git clone https://github.com/itaygil3/echo-security-scanner.git
cd echo-security-scanner
docker compose up -d --build
```

On startup the scheduler enqueues all 10 images. The first round takes a minute or two, because Trivy downloads
its vulnerability DB into the `trivy-cache` volume first. Follow it with:

```bash
docker compose ps                    # all services up, postgres/rabbitmq/api healthy
docker compose logs -f scanner       # "Scanned nginx:1.19 in 6.2s: 414 findings, 269 unique CVEs"
curl localhost:8000/api/images       # scan_status goes PENDING -> SCANNING -> SUCCESS
```

Interactive API docs (Swagger) are at http://localhost:8000/docs.

**Useful commands**

```bash
docker compose down        # stop (data is kept in volumes)
docker compose down -v     # stop and delete all data; the DB is re-created and re-seeded on next start
docker compose restart scheduler   # trigger a new scan round now
```

> The schema is created by `db/init/*.sql` only when the Postgres volume is empty. After pulling schema changes,
> run `docker compose down -v`.

## End-to-end verification checklist

Run these after `docker compose up -d --build` to check the whole system works.

- [ ] **All services are up.** `docker compose ps` shows 5 services running, and `postgres`, `rabbitmq` and
  `api` are `healthy`.
- [ ] **The API is healthy.** `curl localhost:8000/health` returns `{"status":"ok"}`.
- [ ] **The scheduler queued every image.** `docker compose logs scheduler` shows
  `Published 10 scan requests to 'scan_requests'`.
- [ ] **The worker scanned them.** `docker compose logs scanner` shows `Scanned <image> in …` and
  `Stored … findings for <image>` for each image.
- [ ] **Every image has results.** In `curl localhost:8000/api/images`, all 10 images have
  `"scan_status": "SUCCESS"`, a `last_scan_at`, and non-zero `severity_counts.total`.
- [ ] **Per-image CVEs and the severity filter work.**
  `curl 'localhost:8000/api/images/redis/6.0/cves?severity=CRITICAL'` returns only `CRITICAL` entries, each
  with package name, installed version and fixed version.
- [ ] **Unique CVEs work.** `curl localhost:8000/api/cves` lists each CVE once, and
  `curl 'localhost:8000/api/cves?severity=CRITICAL'` returns a shorter list.
- [ ] **CVE to images works.** `curl localhost:8000/api/cves/CVE-2022-37434/images` lists `alpine:3.12` and
  `nginx:1.19` with their packages.
- [ ] **Errors are handled.** `curl localhost:8000/api/images/nginx/nope/cves` returns 404, and
  `curl 'localhost:8000/api/cves?severity=SEVERE'` returns 422.
- [ ] **A failed scan is recorded, not crashed on.** Add an image that doesn't exist and start a new round:

  ```bash
  docker compose exec postgres psql -U echo -d echo \
    -c "INSERT INTO images (name, tag) VALUES ('nginx', 'does-not-exist');"
  docker compose restart scheduler
  ```

  Within a minute `/api/images` shows it as `"scan_status": "FAILED"` with
  `"last_error": "Image nginx:does-not-exist not found: …"`, and the other images keep scanning. Clean up with
  `DELETE FROM images WHERE tag = 'does-not-exist';`.
- [ ] **The automated e2e tests pass.** `poetry run pytest -m e2e` (see [Development](#development)).

## Configuration

Settings are environment variables, read by `echo_common.config.Settings`. Compose provides defaults. To change
them, copy `.env.example` to `.env` and edit it.

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://echo:echo@postgres:5432/echo` | all | Async SQLAlchemy URL |
| `RABBITMQ_URL` | `amqp://echo:echo@rabbitmq:5672/%2F` | scheduler, scanner | Broker URL |
| `SCAN_QUEUE` | `scan_requests` | scheduler, scanner | Queue name (DLQ: `<name>.dlq`) |
| `SCAN_INTERVAL_SECONDS` | `900` | scheduler | Time between scan rounds |
| `SCANNER_CONCURRENCY` | `1` | scanner (compose) | Max scans running at once in one worker |
| `LOG_LEVEL` | `INFO` | all | Python log level |

The worker's options are command-line flags, set in `docker-compose.yml`:

```bash
python -m scanner --scanner trivy --concurrency 1 --timeout 600
```

The images to scan are the rows of the `images` table, seeded by `db/init/02_seed_images.sql` with:
`nginx:1.19`, `postgres:12`, `redis:6.0`, `node:14-alpine`, `python:3.8-slim`, `alpine:3.12`, `ubuntu:20.04`,
`mysql:8.0`, `mongo:4.4`, `httpd:2.4`.

## API

Base URL `http://localhost:8000`. All responses are JSON. Severity values are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
and `UNKNOWN`. Any other `severity` value returns **422**.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/api/images` | All images with CVE counts per severity |
| GET | `/api/images/{image_name}/{tag}/cves?severity=` | CVEs in one image, with package details |
| GET | `/api/cves?severity=` | Unique CVEs across all images |
| GET | `/api/cves/{cve_id}/images` | Images affected by a CVE, with package details |

The examples below are real responses from a scan of the 10 images. Long lists are shortened.

### `GET /health`

`200 {"status": "ok"}`, or **503** `{"status": "error"}` when the database is unreachable.

```bash
curl localhost:8000/health
```
```json
{"status": "ok"}
```

### `GET /api/images`

Every image with its last scan state and the number of **distinct CVEs per severity**.

```bash
curl localhost:8000/api/images
```
```json
[
  {
    "name": "redis",
    "tag": "6.0",
    "scan_status": "SUCCESS",
    "last_scan_at": "2026-11-19T14:29:04.779770Z",
    "last_error": null,
    "severity_counts": {"CRITICAL": 11, "HIGH": 96, "MEDIUM": 167, "LOW": 83, "UNKNOWN": 5, "total": 362}
  },
  {
    "name": "alpine",
    "tag": "3.12",
    "scan_status": "SUCCESS",
    "last_scan_at": "2026-11-19T14:29:09.053681Z",
    "last_error": null,
    "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "total": 1}
  }
]
```

`scan_status` is one of `PENDING`, `SCANNING`, `SUCCESS` or `FAILED`. When a scan failed, `last_error` says why,
and the image keeps the findings from its last successful scan.

### `GET /api/images/{image_name}/{tag}/cves`

CVEs found in one image, **one entry per affected package**, most severe first.
- Optional `severity` filter.
- **404** if the image isn't tracked.
- Image names containing `/` work too (e.g. `/api/images/bitnami/redis/7.0/cves`).

```bash
curl localhost:8000/api/images/alpine/3.12/cves
curl 'localhost:8000/api/images/redis/6.0/cves?severity=CRITICAL'     # 11 results
```
```json
[
  {
    "cve_id": "CVE-2022-37434",
    "severity": "CRITICAL",
    "title": "zlib: heap-based buffer over-read and overflow in inflate() in inflate.c via a large gzip header extra field",
    "description": "zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c ...",
    "primary_url": "https://avd.aquasec.com/nvd/cve-2022-37434",
    "package_name": "zlib",
    "package_type": "alpine",
    "installed_version": "1.2.12-r0",
    "fixed_version": "1.2.12-r2"
  }
]
```

`fixed_version` is `null` when no fix is available. It may list several versions (e.g. `"1.19.8, 1.20.3"`).

```bash
curl localhost:8000/api/images/nginx/nope/cves
```
```json
{"detail": "Image nginx:nope not found"}
```

### `GET /api/cves`

Unique CVEs across all images, most severe first.
- `severity` in each entry is the **highest** the CVE was found with in any image.
- With `?severity=X`, the list holds CVEs found with severity X in at least one image.

```bash
curl localhost:8000/api/cves                      # 959 CVEs
curl 'localhost:8000/api/cves?severity=CRITICAL'  # 49 CVEs
```
```json
[
  {
    "cve_id": "CVE-2018-25009",
    "severity": "CRITICAL",
    "title": "libwebp: out-of-bounds read in WebPMuxCreateInternal",
    "primary_url": "https://avd.aquasec.com/nvd/cve-2018-25009"
  },
  {
    "cve_id": "CVE-2018-25010",
    "severity": "CRITICAL",
    "title": "libwebp: out-of-bounds read in ApplyFilter()",
    "primary_url": "https://avd.aquasec.com/nvd/cve-2018-25010"
  }
]
```

### `GET /api/cves/{cve_id}/images`

Every image affected by a CVE, with the package that carries it and **that image's severity**. Returns **404** if
the CVE wasn't found in any image.

```bash
curl localhost:8000/api/cves/CVE-2022-37434/images
```
```json
[
  {
    "image_name": "alpine",
    "image_tag": "3.12",
    "severity": "CRITICAL",
    "package_name": "zlib",
    "package_type": "alpine",
    "installed_version": "1.2.12-r0",
    "fixed_version": "1.2.12-r2"
  },
  {
    "image_name": "nginx",
    "image_tag": "1.19",
    "severity": "CRITICAL",
    "package_name": "zlib1g",
    "package_type": "debian",
    "installed_version": "1:1.2.11.dfsg-1",
    "fixed_version": "1:1.2.11.dfsg-1+deb10u2"
  }
]
```

## Database schema

Defined in [`db/init/01_schema.sql`](db/init/01_schema.sql) and mirrored as SQLAlchemy Core tables in
`common/echo_common/db/tables/`.

```mermaid
erDiagram
    images ||--o{ image_cves : "has findings"
    cves ||--o{ image_cves : "found as"
    packages ||--o{ image_cves : "affected"

    images {
        serial id PK
        varchar name "UNIQUE (name, tag)"
        varchar tag
        timestamptz last_scan_at
        varchar scan_status "PENDING | SCANNING | SUCCESS | FAILED"
        text last_error
        timestamptz created_at
        timestamptz updated_at
    }
    cves {
        varchar id PK "CVE-YYYY-NNNN"
        text title
        text description
        text primary_url
        varchar source "scanner, e.g. trivy"
    }
    packages {
        serial id PK
        varchar name "UNIQUE (name, type)"
        varchar type "debian, alpine, python-pkg, gobinary, ..."
    }
    image_cves {
        serial id PK
        int image_id FK
        varchar cve_id FK
        int package_id FK
        varchar installed_version
        varchar fixed_version "NULL = no fix"
        smallint severity "0 UNKNOWN .. 4 CRITICAL"
        timestamptz detected_at
    }
```

| Table | Holds |
|---|---|
| `images` | The images to scan: name, tag, last scan timestamp, scan status and last error |
| `cves` | One row per unique CVE: title, description, reference URL and the scanner that reported it |
| `packages` | One row per OS or language package (`name` + `type`) |
| `image_cves` | The image ↔ CVE relationship: which package and installed version carries the CVE, the fixed version, and the severity |

**Design notes**
- **Severity is stored per finding (`image_cves`), not per CVE.** Trivy takes severity from the data source for
  the package's distribution and prefers vendor ratings over NVD
  ([Trivy docs: Severity Selection](https://trivy.dev/docs/latest/guide/scanner/vulnerability/#severity-selection)).
  So the same CVE can differ by image: CVE-2026-13595 is MEDIUM on the Debian-based images and HIGH on `mysql:8.0`
  (Oracle Linux).
- **Severity is a `SMALLINT`** using Trivy's numeric mapping (`0` UNKNOWN, `1` LOW, `2` MEDIUM, `3` HIGH,
  `4` CRITICAL), so "most severe" is a plain `max()` / `ORDER BY severity DESC`. In Python it's an `IntEnum`, and
  the API returns names.
- **A finding is unique per** `(image_id, cve_id, package_id, installed_version)`. The same CVE in two packages
  of one image (e.g. `openssl` and `libssl1.1`) gives two rows. Duplicates reported by the scanner are dropped by
  the database (`ON CONFLICT DO NOTHING`).
- **Only `CVE-*` identifiers are stored.** Other advisory IDs (GHSA-, DLA-, …) are skipped, as are entries
  without a package name or installed version.
- **Rescans replace an image's findings atomically.** The delete and insert run in one transaction, so a failed
  insert never leaves the image without results.

## How scanning works

```mermaid
sequenceDiagram
    participant S as scheduler
    participant Q as RabbitMQ
    participant W as scanner worker
    participant T as Trivy
    participant DB as PostgreSQL
    S->>DB: read images
    S->>Q: publish ScanRequest per image (persistent)
    Q->>W: deliver (prefetch = concurrency)
    W->>DB: status SCANNING
    W->>T: trivy image --format json --scanners vuln <image>
    T-->>W: JSON report
    W->>DB: upsert CVEs + packages, replace findings, status SUCCESS
    W->>Q: ack (message deleted)
```

- **Generic scanners:**
  - `BaseScanner` (`services/scanner/scanner/scanners/base.py`) is an async interface with a per-scan timeout.
  - `TrivyScanner` runs the Trivy CLI as an asyncio subprocess and parses its JSON report. Trivy has no Python
    SDK, and the JSON report is its documented integration format.
  - New scanners are added to the `ScannerType` enum and the registry, then picked per worker with `--scanner`.
- **Concurrency:** each message is handled in a background task. An `asyncio.Semaphore` limits how many scans run
  at once, and RabbitMQ prefetch matches it.
- **Failure handling:**

| Situation | Image | Message |
|---|---|---|
| Scan succeeded | `SUCCESS`, findings replaced | ack (deleted) |
| Image not found / Trivy error / timeout | `FAILED` + `last_error`, previous findings kept | ack (retried next round) |
| Image already `SCANNING` (another request for it is running) | unchanged, not scanned twice | ack (deleted) |
| Invalid message | unchanged | rejected → `scan_requests.dlq` |
| Unexpected error | `FAILED`, previous findings kept | rejected → `scan_requests.dlq` |
| Worker stopped mid-scan | stays `SCANNING` until the message is redelivered | not acked → requeued; the redelivery takes the scan over |

- **No duplicate scans:** the scheduler doesn't queue images that are `SCANNING`, and the worker moves an image to
  `SCANNING` only if it isn't already (one atomic `UPDATE`), so two requests for one image never scan it at once.

- **Graceful shutdown:** on SIGTERM the worker stops consuming and waits up to 30s for running scans. The
  scheduler's wait ends immediately.

## Development

```bash
poetry install                       # one in-project .venv with common + all services + dev tools
docker compose up -d postgres        # DB tests create a fresh echo_test database from db/init/*.sql
poetry run pytest                    # unit, DB, worker, scheduler and API tests
poetry run ruff check . && poetry run ruff format --check .
```

End-to-end tests publish real scan requests and check what the running stack stored:

```bash
docker compose up -d --build
poetry run pytest -m e2e
```

DB tests are skipped when Postgres isn't reachable. The e2e tests are excluded from the default run.

**Project layout**

```
common/echo_common/      shared package: config, enums, models/, db/ (engine, tables/, repositories/), messaging/
db/                      Postgres image + init SQL (schema, seed)
services/scheduler/      scheduler service       (publisher.py, runner.py)
services/scanner/        scanner worker          (scanners/ base + trivy + registry, worker.py)
services/api/            REST API                (main.py, routers/, schemas/)
tests/e2e/               end-to-end tests against the compose stack
docker-compose.yml       the whole system
```

## Known limitations

- **Docker Hub rate limit.** Scanning 10 public images every 15 minutes anonymously can exceed Docker Hub's
  unauthenticated pull limit (`TOOMANYREQUESTS`). Affected images are marked `FAILED` and retried next round.
  The error is currently reported as "Image … not found". Trivy supports registry credentials via
  `TRIVY_USERNAME` / `TRIVY_PASSWORD`, which aren't wired in yet.
- **Concurrent scans and the Trivy DB.** With `SCANNER_CONCURRENCY` > 1, two scans can collide while Trivy
  downloads or refreshes its vulnerability DB. The affected scan fails and is retried next round, so the default
  is 1.
- **No pagination or authentication** on the API.