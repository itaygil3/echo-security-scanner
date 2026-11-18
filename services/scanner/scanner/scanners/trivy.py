import asyncio
import json
import logging
from typing import Any

from pydantic import ValidationError

from echo_common.enums import ScannerType, Severity
from echo_common.models import CVE, ImageRef, Package
from scanner.models import Finding
from scanner.scanners.base import BaseScanner
from scanner.scanners.errors import ImageNotFoundError, ScannerExecutionError, ScannerTimeoutError

logger = logging.getLogger(__name__)

# Fragments of Trivy / registry error messages meaning the image or tag does not exist.
_NOT_FOUND_MARKERS = (
    "manifest unknown",
    "not found",
    "unable to find the specified image",
    "repository does not exist",
    "name unknown",
)
_TIMEOUT_MARKERS = ("deadline exceeded", "timeout")


class TrivyScanner(BaseScanner):
    """Scans images with the Trivy CLI (`trivy image --format json`), run as an asyncio subprocess.

    Trivy has no Python SDK; the CLI's JSON report is its documented integration format.
    Trivy pulls the image straight from the registry, so no Docker daemon is needed.
    `trivy` must be on PATH; its cache location is configured through Trivy's own TRIVY_CACHE_DIR env var.
    """

    name = ScannerType.TRIVY

    async def _scan(self, image: ImageRef) -> list[Finding]:
        raw = await self._run(image)
        try:
            return self._parse_report(raw)
        except ValueError as exc:
            raise ScannerExecutionError(f"Trivy returned an unreadable report for {image}") from exc

    def _command(self, image: ImageRef) -> list[str]:
        return [
            "trivy",
            "image",
            "--format",
            "json",
            "--quiet",
            "--scanners",
            "vuln",
            "--timeout",
            f"{self.timeout_seconds}s",
            str(image),
        ]

    async def _run(self, image: ImageRef) -> bytes:
        try:
            proc = await asyncio.create_subprocess_exec(
                *self._command(image),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ScannerExecutionError("Trivy binary not found on PATH") from exc

        try:
            stdout, stderr = await proc.communicate()
        except asyncio.CancelledError:
            # Cancelled by BaseScanner's timeout (or shutdown): don't leave Trivy running.
            proc.kill()
            await proc.wait()
            raise

        if proc.returncode != 0:
            self._raise_for_failure(image, proc.returncode, stderr.decode(errors="replace"))
        return stdout

    @staticmethod
    def _raise_for_failure(image: ImageRef, returncode: int | None, stderr: str) -> None:
        stderr = stderr.strip()
        message = stderr.splitlines()[-1] if stderr else f"exit code {returncode}"
        lowered = stderr.lower()
        if any(marker in lowered for marker in _NOT_FOUND_MARKERS):
            raise ImageNotFoundError(f"Image {image} not found: {message}")
        if any(marker in lowered for marker in _TIMEOUT_MARKERS):
            raise ScannerTimeoutError(f"Trivy timed out scanning {image}: {message}")
        raise ScannerExecutionError(f"Trivy failed scanning {image}: {message}")

    def _parse_report(self, raw: str | bytes) -> list[Finding]:
        """Convert a Trivy JSON report into findings.

        Entries failing validation are skipped: non-CVE ids (GHSA-, DLA-, ...) and entries without a
        package name or installed version (Trivy marks every field as optional in its JSON output).
        Raises ValueError if the report is not valid JSON.
        """
        report: dict[str, Any] = json.loads(raw)
        findings: list[Finding] = []
        skipped = 0
        for result in report.get("Results") or []:
            # The package type lives on the enclosing result: debian, alpine, python-pkg, node-pkg, ...
            package_type = result.get("Type") or "unknown"
            for vuln in result.get("Vulnerabilities") or []:
                try:
                    findings.append(self._parse_vulnerability(vuln, package_type))
                except ValidationError:
                    skipped += 1
        if skipped:
            logger.info("Skipped %d non-CVE or incomplete Trivy findings", skipped)
        return findings

    def _parse_vulnerability(self, vuln: dict[str, Any], package_type: str) -> Finding:
        """Build a finding from one entry of a Trivy result's `Vulnerabilities` list."""
        return Finding(
            cve=CVE(
                id=vuln.get("VulnerabilityID") or "",
                title=vuln.get("Title"),
                description=vuln.get("Description"),
                primary_url=vuln.get("PrimaryURL"),
                source=self.name,
            ),
            package=Package(name=vuln.get("PkgName") or "", type=package_type),
            installed_version=vuln.get("InstalledVersion") or "",
            fixed_version=vuln.get("FixedVersion") or None,
            # Trivy's severity is per data source (vendor first, e.g. debian, oracle-oval; see SeveritySource),
            # so it belongs to this finding, not to the CVE.
            severity=Severity.parse(vuln.get("Severity")),
        )
