from datetime import datetime

from pydantic import Field

from echo_common.enums import Severity
from echo_common.models.base import CVE_ID_PATTERN, DomainModel


class ImageCVE(DomainModel):
    """Row of `image_cves`: a CVE found in an image through a specific package version.

    Trivy detects image vulnerabilities by matching installed packages, so package and
    installed version are mandatory; fixed version is empty when no fix exists.
    Severity is per finding: the scanner rates a CVE for this image's distribution / package source.
    """

    id: int | None = None
    image_id: int
    cve_id: str = Field(pattern=CVE_ID_PATTERN, max_length=64)
    package_id: int
    installed_version: str = Field(min_length=1, max_length=255)
    fixed_version: str | None = Field(default=None, max_length=255)
    severity: Severity
    detected_at: datetime | None = None
