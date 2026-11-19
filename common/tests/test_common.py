import pytest

from echo_common.config import Settings
from echo_common.enums import Severity


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("SCAN_QUEUE", "q1")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    s = Settings(_env_file=None)
    assert s.scan_queue == "q1"
    assert s.log_level == "DEBUG"
    assert s.scan_interval_seconds == 900


def test_scan_interval_must_be_positive(monkeypatch):
    monkeypatch.setenv("SCAN_INTERVAL_SECONDS", "0")
    with pytest.raises(ValueError):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("HIGH", Severity.HIGH), ("critical", Severity.CRITICAL), ("weird", Severity.UNKNOWN), (None, Severity.UNKNOWN)],
)
def test_severity_parse(raw, expected):
    assert Severity.parse(raw) is expected


def test_severity_is_ordered():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.UNKNOWN
    assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL
    assert Severity(3) is Severity.HIGH and Severity["HIGH"] is Severity.HIGH
