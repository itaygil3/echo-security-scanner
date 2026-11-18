import pytest

from echo_common.db.repositories import CVERepository, ImageCVERepository, ImageRepository, PackageRepository
from echo_common.db.tables import images
from echo_common.enums import ScannerType, ScanStatus, Severity
from echo_common.models import CVE, ImageCVE, ImageRef, Package


def _cve(cve_id: str, severity: Severity = Severity.HIGH, title: str = "t") -> CVE:
    return CVE(id=cve_id, severity=severity, title=title, source=ScannerType.TRIVY)


async def test_seeded_images(database):
    async with database.session() as session:
        repo = ImageRepository(session)
        all_images = await repo.list_all()
        nginx = await repo.get_by_ref(ImageRef.parse("nginx:1.19"))
        missing = await repo.get_by_ref(ImageRef.parse("nginx:nope"))

    assert len(all_images) == 10
    assert {str(i) for i in all_images} >= {"nginx:1.19", "node:14-alpine", "httpd:2.4"}
    assert all(i.scan_status is ScanStatus.PENDING and i.last_scan_at is None for i in all_images)
    assert nginx is not None and nginx.id is not None
    assert missing is None


async def test_set_status_lifecycle(database):
    async with database.session() as session:
        repo = ImageRepository(session)
        image = await repo.get_by_ref(ImageRef.parse("redis:6.0"))

        await repo.set_status(image.id, ScanStatus.SCANNING)
        scanning = await repo.get(image.id)
        await repo.set_status(image.id, ScanStatus.FAILED, error="image not found")
        failed = await repo.get(image.id)
        await repo.set_status(image.id, ScanStatus.SUCCESS)
        success = await repo.get(image.id)

    assert scanning.scan_status is ScanStatus.SCANNING and scanning.last_scan_at is None
    assert failed.scan_status is ScanStatus.FAILED and failed.last_error == "image not found"
    assert failed.last_scan_at is not None
    assert success.scan_status is ScanStatus.SUCCESS and success.last_error is None


async def test_cve_upsert_dedupes_and_refreshes(database):
    async with database.session() as session:
        repo = CVERepository(session)
        # Same CVE twice in one batch (e.g. reported for openssl and libssl1.1).
        await repo.upsert_many([_cve("CVE-2021-3711"), _cve("CVE-2021-3711"), _cve("CVE-2022-1304")])
        await repo.upsert_many([_cve("CVE-2021-3711", Severity.CRITICAL, title="updated")])
        stored = {c.id: c for c in await repo.list_all()}

    assert set(stored) == {"CVE-2021-3711", "CVE-2022-1304"}
    assert stored["CVE-2021-3711"].severity is Severity.CRITICAL
    assert stored["CVE-2021-3711"].title == "updated"
    assert stored["CVE-2021-3711"].source is ScannerType.TRIVY


async def test_package_ensure_many_is_idempotent(database):
    pkgs = [Package(name="openssl", type="debian"), Package(name="openssl", type="debian"), Package(name="pip")]
    async with database.session() as session:
        repo = PackageRepository(session)
        first = await repo.ensure_many(pkgs)
        second = await repo.ensure_many([Package(name="openssl", type="debian")])
        count = len(await repo.list_all())

    assert set(first) == {("openssl", "debian"), ("pip", "unknown")}
    assert second[("openssl", "debian")] == first[("openssl", "debian")]
    assert count == 2


async def test_replace_findings_for_image(database):
    async with database.session() as session:
        image = await ImageRepository(session).get_by_ref(ImageRef.parse("nginx:1.19"))
        await CVERepository(session).upsert_many([_cve("CVE-2021-3711"), _cve("CVE-2022-1304")])
        ids = await PackageRepository(session).ensure_many([Package(name="openssl", type="debian")])
        pkg_id = ids[("openssl", "debian")]
        repo = ImageCVERepository(session)

        finding = ImageCVE(image_id=image.id, cve_id="CVE-2021-3711", package_id=pkg_id, installed_version="1.1.1d")
        # Duplicate finding is dropped by the unique constraint.
        await repo.replace_for_image(image.id, [finding, finding])
        first = await repo.list_for_image(image.id)

        newer = ImageCVE(
            image_id=image.id,
            cve_id="CVE-2022-1304",
            package_id=pkg_id,
            installed_version="1.1.1d",
            fixed_version="1.1.1e",
        )
        await repo.replace_for_image(image.id, [newer])
        second = await repo.list_for_image(image.id)

        await repo.replace_for_image(image.id, [])
        cleared = await repo.list_for_image(image.id)

    assert [(f.cve_id, f.fixed_version) for f in first] == [("CVE-2021-3711", None)]
    assert first[0].detected_at is not None
    assert [(f.cve_id, f.fixed_version) for f in second] == [("CVE-2022-1304", "1.1.1e")]
    assert cleared == []


async def test_generic_update_and_delete_return_rowcounts(database):
    async with database.session() as session:
        repo = ImageRepository(session)
        updated = await repo.update_where({"last_error": "x"}, images.c.name.in_(["nginx", "redis"]))
        deleted = await repo.delete_where(images.c.name == "httpd")
        remaining = len(await repo.list_all())

    assert (updated, deleted, remaining) == (2, 1, 9)


async def test_session_rolls_back_on_error(database):
    with pytest.raises(RuntimeError):
        async with database.session() as session:
            await CVERepository(session).upsert_many([_cve("CVE-2020-0001")])
            raise RuntimeError("scan persistence failed")

    async with database.session() as session:
        assert await CVERepository(session).get("CVE-2020-0001") is None
