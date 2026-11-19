from enum import IntEnum, StrEnum


class Severity(IntEnum):
    """Vulnerability severity; values follow Trivy's numeric mapping, so severities compare and sort naturally."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str | None) -> "Severity":
        """Severity from a scanner's name (case-insensitive); UNKNOWN if missing or unrecognized."""
        return cls.__members__.get((name or "").upper(), cls.UNKNOWN)


class ScanStatus(StrEnum):
    """Lifecycle of an image scan."""

    PENDING = "PENDING"
    SCANNING = "SCANNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ScannerType(StrEnum):
    """Available vulnerability scanner implementations."""

    TRIVY = "trivy"
