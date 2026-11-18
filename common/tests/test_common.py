import pytest

from echo_common.config import ImageRef, Settings
from echo_common.enums import Severity


@pytest.mark.parametrize(
    ("ref", "name", "tag"),
    [
        ("nginx:1.19", "nginx", "1.19"),
        ("redis", "redis", "latest"),
        ("localhost:5000/app", "localhost:5000/app", "latest"),
        ("localhost:5000/app:2", "localhost:5000/app", "2"),
    ],
)
def test_image_ref_parse(ref, name, tag):
    parsed = ImageRef.parse(ref)
    assert (parsed.name, parsed.tag) == (name, tag)
    assert str(parsed) == f"{name}:{tag}"


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


def test_severity_case_insensitive_constructor():
    assert Severity("low") is Severity.LOW
