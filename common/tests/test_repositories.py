import pytest
from sqlalchemy.exc import IntegrityError

from echo_common.db.repositories import CVERepository, ImageCVERepository, ImageRepository, PackageRepository
from echo_common.db.tables import images
from echo_common.enums import ScannerType, ScanStatus, Severity
from echo_common.models import CVE, ImageCVE, ImageRef, Package

# Upsert parameters as the worker passes them.
CVE_UPSERT = {"conflict_on": ["id"], "update": ["severity", "title", "description", "primary_url", "source"]}
PACKAGE_UPSERT = {"conflict_on": ["name", "type"]}
OPENSSL = Package(name="openssl", type="debian")


def _cve(cve_id: str, severity: Severity = Severity.HIGH, title: str = "t") -> CVE:
    return CVE(id=cve_id, severity=severity, title=title, source=ScannerType.TRIVY)


async def _stored_openssl_id(engine) -> int:
    packages = PackageRepository(engine)
    await packages.upsert_many([OPENSSL], **PACKAGE_UPSERT)
    return (await packages.get_ids([OPENSSL]))[("openssl", "debian")]


async def test_seeded_images(engine):
    repo = ImageRepository(engine)
    all_images = await repo.list_all()
    nginx = await repo.get_by_ref(ImageRef.parse("nginx:1.19"))
    missing = await repo.get_by_ref(ImageRef.parse("nginx:nope"))

    assert len(all_images) == 10
    assert {str(i) for i in all_images} >= {"nginx:1.19", "node:14-alpine", "httpd:2.4"}
    assert all(i.scan_status is ScanStatus.PENDING and i.last_scan_at is None for i in all_images)
    assert nginx is not None and nginx.id is not None
    assert missing is None


async def test_set_status_lifecycle(engine):
    repo = ImageRepository(engine)
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


async def test_cve_upsert_dedupes_and_refreshes(engine):
    repo = CVERepository(engine)
    # Same CVE twice in one batch (e.g. reported for openssl and libssl1.1).
    await repo.upsert_many([_cve("CVE-2021-3711"), _cve("CVE-2021-3711"), _cve("CVE-2022-1304")], **CVE_UPSERT)
    await repo.upsert_many([_cve("CVE-2021-3711", Severity.CRITICAL, title="updated")], **CVE_UPSERT)
    stored = {c.id: c for c in await repo.list_all()}

    assert set(stored) == {"CVE-2021-3711", "CVE-2022-1304"}
    assert stored["CVE-2021-3711"].severity is Severity.CRITICAL
    assert stored["CVE-2021-3711"].title == "updated"
    assert stored["CVE-2021-3711"].source is ScannerType.TRIVY


async def test_package_upsert_many_is_idempotent(engine):
    repo = PackageRepository(engine)
    pkgs = [OPENSSL, OPENSSL, Package(name="pip")]
    await repo.upsert_many(pkgs, **PACKAGE_UPSERT)
    first = await repo.get_ids(pkgs)
    await repo.upsert_many([OPENSSL], **PACKAGE_UPSERT)
    second = await repo.get_ids([OPENSSL])

    assert set(first) == {("openssl", "debian"), ("pip", "unknown")}
    assert second == {("openssl", "debian"): first[("openssl", "debian")]}
    assert len(await repo.list_all()) == 2
    assert await repo.get_ids([]) == {}


async def test_replace_findings_for_image(engine):
    image = await ImageRepository(engine).get_by_ref(ImageRef.parse("nginx:1.19"))
    await CVERepository(engine).upsert_many([_cve("CVE-2021-3711"), _cve("CVE-2022-1304")], **CVE_UPSERT)
    pkg_id = await _stored_openssl_id(engine)
    repo = ImageCVERepository(engine)

    finding = ImageCVE(image_id=image.id, cve_id="CVE-2021-3711", package_id=pkg_id, installed_version="1.1.1d")
    # Duplicate finding is dropped by the unique constraint.
    await repo.replace_for_image(image.id, [finding, finding])
    first = await repo.list_for_image(image.id)

    newer = ImageCVE(
        image_id=image.id, cve_id="CVE-2022-1304", package_id=pkg_id, installed_version="1.1.1d", fixed_version="1.1.1e"
    )
    await repo.replace_for_image(image.id, [newer])
    second = await repo.list_for_image(image.id)

    await repo.replace_for_image(image.id, [])
    cleared = await repo.list_for_image(image.id)

    assert [(f.cve_id, f.fixed_version) for f in first] == [("CVE-2021-3711", None)]
    assert first[0].detected_at is not None
    assert [(f.cve_id, f.fixed_version) for f in second] == [("CVE-2022-1304", "1.1.1e")]
    assert cleared == []


async def test_replace_findings_is_atomic(engine):
    image = await ImageRepository(engine).get_by_ref(ImageRef.parse("nginx:1.19"))
    await CVERepository(engine).upsert_many([_cve("CVE-2021-3711")], **CVE_UPSERT)
    pkg_id = await _stored_openssl_id(engine)
    repo = ImageCVERepository(engine)

    kept = ImageCVE(image_id=image.id, cve_id="CVE-2021-3711", package_id=pkg_id, installed_version="1.1.1d")
    await repo.replace_for_image(image.id, [kept])

    # CVE not in the cves table -> FK violation after the delete already ran.
    broken = ImageCVE(image_id=image.id, cve_id="CVE-1999-0001", package_id=pkg_id, installed_version="1.0")
    with pytest.raises(IntegrityError):
        await repo.replace_for_image(image.id, [broken])

    # The delete was rolled back together with the failed insert.
    assert [f.cve_id for f in await repo.list_for_image(image.id)] == ["CVE-2021-3711"]


async def test_generic_update_and_delete_return_rowcounts(engine):
    repo = ImageRepository(engine)
    updated = await repo.update_where({"last_error": "x"}, images.c.name.in_(["nginx", "redis"]))
    deleted = await repo.delete_where(images.c.name == "httpd")

    assert (updated, deleted, len(await repo.list_all())) == (2, 1, 9)
