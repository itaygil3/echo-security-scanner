from typing import Annotated, Literal

from fastapi import Depends, Query

from echo_common.enums import Severity

SeverityName = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def severity_filter(
    severity: Annotated[SeverityName | None, Query(description="Only findings with this severity")] = None,
) -> Severity | None:
    """`?severity=HIGH` -> Severity.HIGH (anything else is rejected with 422 by FastAPI)."""
    return Severity[severity] if severity else None


SeverityFilter = Annotated[Severity | None, Depends(severity_filter)]
