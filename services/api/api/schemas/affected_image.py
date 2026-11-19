from pydantic import BaseModel, Field


class AffectedImage(BaseModel):
    """An image affected by a CVE, with the package that carries it."""

    image_name: str
    image_tag: str
    severity: str = Field(examples=["HIGH"])
    package_name: str
    package_type: str
    installed_version: str
    fixed_version: str | None
