from echo_common.enums import Severity
from echo_common.models.base import DomainModel


class FindingDetail(DomainModel):
    """Read model: one `image_cves` row joined with its image, CVE and package."""

    image_id: int
    image_name: str
    image_tag: str
    cve_id: str
    cve_title: str | None = None
    cve_description: str | None = None
    cve_primary_url: str | None = None
    package_name: str
    package_type: str
    installed_version: str
    fixed_version: str | None = None
    severity: Severity
