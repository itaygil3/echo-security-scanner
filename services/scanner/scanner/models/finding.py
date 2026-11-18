from pydantic import Field

from echo_common.enums import Severity
from echo_common.models import CVE, DomainModel, Package


class Finding(DomainModel):
    """One vulnerability found in an image: a CVE affecting a specific installed package version."""

    cve: CVE
    package: Package
    installed_version: str = Field(min_length=1)
    fixed_version: str | None = None
    severity: Severity = Field(description="Severity of the CVE as rated for this image's package source")
