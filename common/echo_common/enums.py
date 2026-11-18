from enum import StrEnum


class Severity(StrEnum):
    """Vulnerability severity levels as reported by scanners."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        """Map any scanner-provided value to a Severity, falling back to UNKNOWN."""
        if not value:
            return cls.UNKNOWN
        try:
            return cls(value.strip().upper())
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def _missing_(cls, value: object) -> "Severity | None":
        # Allow case-insensitive construction, e.g. Severity("high").
        if isinstance(value, str):
            upper = value.strip().upper()
            for member in cls:
                if member.value == upper:
                    return member
        return None


class ScanStatus(StrEnum):
    """Lifecycle of an image scan."""

    PENDING = "PENDING"
    SCANNING = "SCANNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ScannerType(StrEnum):
    """Available vulnerability scanner implementations (selected with SCANNER_TYPE)."""

    TRIVY = "trivy"
