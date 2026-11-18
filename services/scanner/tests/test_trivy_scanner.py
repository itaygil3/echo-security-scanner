import asyncio
from pathlib import Path

import pytest

from echo_common.enums import ScannerType, Severity
from echo_common.models import ImageRef
from scanner.scanners import (
    ImageNotFoundError,
    ScannerExecutionError,
    ScannerTimeoutError,
    TrivyScanner,
    get_scanner,
)
from scanner.scanners import trivy as trivy_module

REPORT = (Path(__file__).parent / "fixtures" / "trivy_report.json").read_bytes()
IMAGE = ImageRef(name="nginx", tag="1.19")


class FakeProcess:
    def __init__(self, returncode=0, stdout=b"", stderr=b"", hang=False):
        self.returncode = returncode
        self._stdout, self._stderr, self._hang = stdout, stderr, hang
        self.killed = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(3600)
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        return self.returncode


@pytest.fixture
def fake_trivy(monkeypatch):
    """Replace the subprocess call; returns a setter for the fake process and the captured command."""
    state = {"proc": FakeProcess(stdout=REPORT), "cmd": None}

    async def fake_exec(*cmd, **_kwargs):
        state["cmd"] = cmd
        if isinstance(state["proc"], Exception):
            raise state["proc"]
        return state["proc"]

    monkeypatch.setattr(trivy_module.asyncio, "create_subprocess_exec", fake_exec)
    return state


def test_parse_report_keeps_only_valid_cve_findings():
    findings = TrivyScanner()._parse_report(REPORT)

    ids = [(f.cve.id, f.package.name) for f in findings]
    # DLA-, GHSA- ids and the entry without a package name are skipped.
    assert ids == [
        ("CVE-2021-3711", "libssl1.1"),
        ("CVE-2021-3711", "openssl"),
        ("CVE-2022-1304", "e2fsprogs"),
        ("CVE-2022-40897", "setuptools"),
    ]


def test_parse_report_maps_fields():
    by_pkg = {f.package.name: f for f in TrivyScanner()._parse_report(REPORT)}

    ssl = by_pkg["libssl1.1"]
    assert ssl.cve.severity is Severity.CRITICAL
    assert ssl.cve.source is ScannerType.TRIVY
    assert ssl.cve.primary_url == "https://avd.aquasec.com/nvd/cve-2021-3711"
    assert ssl.package.type == "debian"
    assert (ssl.installed_version, ssl.fixed_version) == ("1.1.1d-0+deb10u6", "1.1.1d-0+deb10u7")

    e2fs = by_pkg["e2fsprogs"]
    assert e2fs.cve.severity is Severity.HIGH  # lower-case severity normalized
    assert e2fs.fixed_version is None  # no fix available

    assert by_pkg["setuptools"].package.type == "python-pkg"


def test_parse_report_without_results():
    assert TrivyScanner()._parse_report(b'{"SchemaVersion": 2, "Results": null}') == []


async def test_scan_success(fake_trivy):
    result = await TrivyScanner(timeout_seconds=120).scan(IMAGE)

    assert result.image == IMAGE
    assert result.scanner is ScannerType.TRIVY
    assert len(result.findings) == 4
    cmd = fake_trivy["cmd"]
    assert cmd[:2] == ("trivy", "image")
    assert cmd[-1] == "nginx:1.19"
    assert "--timeout" in cmd and "120s" in cmd


@pytest.mark.parametrize(
    ("stderr", "error"),
    [
        (b'FATAL\tunable to find the specified image "nginx:nope"', ImageNotFoundError),
        (b"MANIFEST_UNKNOWN: manifest unknown", ImageNotFoundError),
        (b"FATAL\tscan error: context deadline exceeded", ScannerTimeoutError),
        (b"FATAL\tdb download failed", ScannerExecutionError),
        (b"", ScannerExecutionError),
    ],
)
async def test_scan_maps_trivy_failures(fake_trivy, stderr, error):
    fake_trivy["proc"] = FakeProcess(returncode=1, stderr=stderr)
    with pytest.raises(error):
        await TrivyScanner().scan(IMAGE)


async def test_scan_invalid_json(fake_trivy):
    fake_trivy["proc"] = FakeProcess(stdout=b"not json")
    with pytest.raises(ScannerExecutionError, match="unreadable report"):
        await TrivyScanner().scan(IMAGE)


async def test_scan_binary_missing(fake_trivy):
    fake_trivy["proc"] = FileNotFoundError("trivy")
    with pytest.raises(ScannerExecutionError, match="not found"):
        await TrivyScanner().scan(IMAGE)


async def test_scan_timeout_kills_trivy(fake_trivy):
    proc = FakeProcess(hang=True)
    fake_trivy["proc"] = proc
    with pytest.raises(ScannerTimeoutError):
        await TrivyScanner(timeout_seconds=1).scan(IMAGE)
    assert proc.killed


def test_get_scanner():
    scanner = get_scanner(ScannerType.TRIVY, timeout_seconds=30)
    assert isinstance(scanner, TrivyScanner)
    assert scanner.timeout_seconds == 30
