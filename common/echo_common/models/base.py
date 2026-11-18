from pydantic import BaseModel, ConfigDict

# Only CVE identifiers are stored; other advisory IDs (GHSA-, DLA-, ...) are dropped by the scanner.
CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,}$"


class DomainModel(BaseModel):
    """Base for all models: can be built from DB rows / ORM objects."""

    model_config = ConfigDict(from_attributes=True, str_strip_whitespace=True)
