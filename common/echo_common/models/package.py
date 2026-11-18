from pydantic import Field

from echo_common.models.base import DomainModel


class Package(DomainModel):
    """Row of `packages`: an OS or language package that can carry vulnerabilities."""

    id: int | None = None
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(default="unknown", min_length=1, max_length=64, examples=["debian", "alpine", "node-pkg"])
