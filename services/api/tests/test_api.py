import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy.ext.asyncio import create_async_engine

from api.main import create_app
from echo_common.db.repositories import CVERepository, ImageCVERepository, ImageRepository, PackageRepository
from echo_common.enums import ScannerType, ScanStatus, Severity
from echo_common.models import CVE, ImageCVE, ImageRef, Package

OPENSSL = Package(name="openssl", type="debian")
ZLIB = Package(name="zlib", type="debian")


async def _client(app):
    """HTTP client running the app's lifespan, so request.state holds the engine and repositories."""
    async with LifespanManager(app) as manager:
        transport = httpx.ASGITransport(app=manager.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


@pytest.fixture
async def client(engine):
    """API client over the test database seeded with a small scan result.

    postgres:12  CVE-2026-13595 MEDIUM (openssl), CVE-2022-37434 CRITICAL (zlib)
    mysql:8.0    CVE-2026-13595 HIGH (openssl)   -- same CVE, other distro severity
    """
    await CVERepository(engine).upsert_many(
        [
            CVE(id="CVE-2026-13595", title="openssl issue", source=ScannerType.TRIVY),
            CVE(id="CVE-2022-37434", title="zlib overflow", primary_url="https://avd.aquasec.com/x", source="trivy"),
        ],
        conflict_on=["id"],
    )
    packages = PackageRepository(engine)
    await packages.upsert_many([OPENSSL, ZLIB], conflict_on=["name", "type"])
    ids = await packages.get_ids([OPENSSL, ZLIB])
    images = ImageRepository(engine)
    postgres = await images.get_by_ref(ImageRef.parse("postgres:12"))
    mysql = await images.get_by_ref(ImageRef.parse("mysql:8.0"))

    def finding(image_id, cve_id, package, severity, fixed=None):
        return ImageCVE(
            image_id=image_id,
            cve_id=cve_id,
            package_id=ids[(package.name, package.type)],
            installed_version="1.0",
            fixed_version=fixed,
            severity=severity,
        )

    image_cves = ImageCVERepository(engine)
    await image_cves.replace_for_image(
        postgres.id,
        [
            finding(postgres.id, "CVE-2026-13595", OPENSSL, Severity.MEDIUM),
            finding(postgres.id, "CVE-2022-37434", ZLIB, Severity.CRITICAL, fixed="1.2.12-r2"),
        ],
    )
    await image_cves.replace_for_image(mysql.id, [finding(mysql.id, "CVE-2026-13595", OPENSSL, Severity.HIGH)])
    await images.set_status(postgres.id, ScanStatus.SUCCESS)
    await images.set_status(mysql.id, ScanStatus.SUCCESS)

    async for client in _client(create_app(engine)):
        yield client


async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


async def test_health_reports_database_down():
    engine = create_async_engine("postgresql+asyncpg://echo:echo@localhost:1/none")
    async for client in _client(create_app(engine)):
        response = await client.get("/health")
    await engine.dispose()
    assert response.status_code == 503
    assert response.json() == {"status": "error", "database": "unreachable"}


async def test_list_images_with_severity_counts(client):
    response = await client.get("/api/images")

    assert response.status_code == 200
    images = {f"{i['name']}:{i['tag']}": i for i in response.json()}
    assert len(images) == 10
    assert images["postgres:12"]["scan_status"] == "SUCCESS"
    assert images["postgres:12"]["severity_counts"] == {
        "CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0, "total": 2,
    }  # fmt: skip
    assert images["mysql:8.0"]["severity_counts"]["HIGH"] == 1
    assert images["nginx:1.19"]["scan_status"] == "PENDING"
    assert images["nginx:1.19"]["severity_counts"]["total"] == 0


async def test_image_cves(client):
    response = await client.get("/api/images/postgres/12/cves")

    assert response.status_code == 200
    body = response.json()
    assert [(c["cve_id"], c["severity"]) for c in body] == [
        ("CVE-2022-37434", "CRITICAL"),
        ("CVE-2026-13595", "MEDIUM"),
    ]
    assert body[0] | {"description": None} == {
        "cve_id": "CVE-2022-37434",
        "severity": "CRITICAL",
        "title": "zlib overflow",
        "description": None,
        "primary_url": "https://avd.aquasec.com/x",
        "package_name": "zlib",
        "package_type": "debian",
        "installed_version": "1.0",
        "fixed_version": "1.2.12-r2",
    }


async def test_image_cves_severity_filter_uses_the_image_severity(client):
    medium = await client.get("/api/images/postgres/12/cves", params={"severity": "MEDIUM"})
    high = await client.get("/api/images/postgres/12/cves", params={"severity": "HIGH"})

    assert [c["cve_id"] for c in medium.json()] == ["CVE-2026-13595"]
    assert high.json() == []  # HIGH only on mysql:8.0


async def test_image_cves_errors(client):
    assert (await client.get("/api/images/nginx/nope/cves")).status_code == 404
    assert (await client.get("/api/images/postgres/12/cves", params={"severity": "SEVERE"})).status_code == 422


async def test_list_cves_unique_with_highest_severity(client):
    response = await client.get("/api/cves")

    assert response.status_code == 200
    assert [(c["cve_id"], c["severity"]) for c in response.json()] == [
        ("CVE-2022-37434", "CRITICAL"),
        ("CVE-2026-13595", "HIGH"),  # highest across images
    ]


async def test_list_cves_severity_filter(client):
    critical = await client.get("/api/cves", params={"severity": "CRITICAL"})
    medium = await client.get("/api/cves", params={"severity": "MEDIUM"})

    assert [c["cve_id"] for c in critical.json()] == ["CVE-2022-37434"]
    assert [(c["cve_id"], c["severity"]) for c in medium.json()] == [("CVE-2026-13595", "MEDIUM")]
    assert (await client.get("/api/cves", params={"severity": "low"})).status_code == 422


async def test_cve_images(client):
    response = await client.get("/api/cves/CVE-2026-13595/images")

    assert response.status_code == 200
    assert response.json() == [
        {
            "image_name": "mysql",
            "image_tag": "8.0",
            "severity": "HIGH",
            "package_name": "openssl",
            "package_type": "debian",
            "installed_version": "1.0",
            "fixed_version": None,
        },
        {
            "image_name": "postgres",
            "image_tag": "12",
            "severity": "MEDIUM",
            "package_name": "openssl",
            "package_type": "debian",
            "installed_version": "1.0",
            "fixed_version": None,
        },
    ]
    assert (await client.get("/api/cves/CVE-1999-0001/images")).status_code == 404
