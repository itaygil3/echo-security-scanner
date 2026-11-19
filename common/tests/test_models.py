from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from echo_common.enums import ScannerType, ScanStatus, Severity
from echo_common.models import CVE, Image, ImageCVE, ImageRef, Package


@pytest.mark.parametrize(
    ("ref", "name", "tag"),
    [
        ("nginx:1.19", "nginx", "1.19"),
        ("redis", "redis", "latest"),
        ("localhost:5000/app", "localhost:5000/app", "latest"),
        ("localhost:5000/app:2", "localhost:5000/app", "2"),
    ],
)
def test_image_ref_parse(ref, name, tag):
    parsed = ImageRef.parse(ref)
    assert (parsed.name, parsed.tag) == (name, tag)
    assert str(parsed) == f"{name}:{tag}"


def test_parse_returns_subclass_instance():
    # `Self` return type: parsing through a subclass builds that subclass.
    image = Image.parse("nginx:1.19")
    assert isinstance(image, Image)
    assert image.scan_status is ScanStatus.PENDING


def test_image_from_db_row():
    row = SimpleNamespace(
        id=1,
        name="nginx",
        tag="1.19",
        last_scan_at=None,
        scan_status="FAILED",
        last_error="boom",
        created_at=None,
        updated_at=None,
    )
    image = Image.model_validate(row)
    assert image.scan_status is ScanStatus.FAILED
    assert str(image) == "nginx:1.19"


def test_cve_accepts_cve_ids():
    cve = CVE(id="CVE-2021-23017", source="trivy")
    assert cve.source is ScannerType.TRIVY
    assert "severity" not in CVE.model_fields  # severity is per finding (ImageCVE)


@pytest.mark.parametrize("bad_id", ["GHSA-xxxx-yyyy-zzzz", "DLA-1234-1", "CVE-21-1", ""])
def test_cve_rejects_non_cve_ids(bad_id):
    with pytest.raises(ValidationError):
        CVE(id=bad_id, source=ScannerType.TRIVY)


@pytest.mark.parametrize("source", [None, "grype-unknown"])
def test_cve_requires_known_source(source):
    with pytest.raises(ValidationError):
        CVE(id="CVE-2021-23017", source=source)


def test_package_requires_name():
    with pytest.raises(ValidationError):
        Package(name="")
    assert Package(name="openssl").type == "unknown"


def test_image_cve_requires_package_installed_version_and_severity():
    ok = ImageCVE(
        image_id=1, cve_id="CVE-2021-3711", package_id=2, installed_version="1.1.1d-0+deb10u6", severity=Severity.HIGH
    )
    assert ok.fixed_version is None
    assert ImageCVE.model_validate({**ok.model_dump(), "severity": 3}).severity is Severity.HIGH  # from a DB row
    with pytest.raises(ValidationError):
        ImageCVE(image_id=1, cve_id="CVE-2021-3711", package_id=2, installed_version="1.0", severity=9)
    with pytest.raises(ValidationError):
        ImageCVE(image_id=1, cve_id="CVE-2021-3711", package_id=2, installed_version="", severity=Severity.LOW)
    with pytest.raises(ValidationError):
        ImageCVE(image_id=1, cve_id="CVE-2021-3711", installed_version="1.0", severity=Severity.LOW)  # no package_id
    with pytest.raises(ValidationError):
        ImageCVE(image_id=1, cve_id="CVE-2021-3711", package_id=2, installed_version="1.0")  # no severity
