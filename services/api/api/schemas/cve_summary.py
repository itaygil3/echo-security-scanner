from pydantic import BaseModel, Field


class CVESummary(BaseModel):
    """A unique CVE found across the scanned images (severity: the highest it was found with)."""

    cve_id: str
    severity: str = Field(examples=["CRITICAL"])
    title: str | None
    primary_url: str | None
