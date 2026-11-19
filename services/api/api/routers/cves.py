from fastapi import APIRouter, HTTPException, Request, status

from api.dependencies import SeverityFilter
from api.schemas import AffectedImage, CVESummary
from echo_common.db.tables import image_cves

router = APIRouter(prefix="/api/cves", tags=["cves"])


@router.get("", response_model=list[CVESummary])
async def list_cves(request: Request, severity: SeverityFilter) -> list[CVESummary]:
    """Unique CVEs across all images, optionally filtered by severity."""
    where = [image_cves.c.severity == severity] if severity is not None else []
    findings = await request.app.state.image_cves.find_details(*where)
    unique: dict[str, CVESummary] = {}
    for f in findings:  # most severe first, so the first finding of a CVE carries its highest severity
        unique.setdefault(
            f.cve_id,
            CVESummary(cve_id=f.cve_id, severity=f.severity.name, title=f.cve_title, primary_url=f.cve_primary_url),
        )
    return list(unique.values())


@router.get("/{cve_id}/images", response_model=list[AffectedImage])
async def cve_images(request: Request, cve_id: str) -> list[AffectedImage]:
    """Images affected by a CVE, with the package details."""
    findings = await request.app.state.image_cves.find_details(image_cves.c.cve_id == cve_id.upper())
    if not findings:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{cve_id} was not found in any image")
    return [
        AffectedImage(
            image_name=f.image_name,
            image_tag=f.image_tag,
            severity=f.severity.name,
            package_name=f.package_name,
            package_type=f.package_type,
            installed_version=f.installed_version,
            fixed_version=f.fixed_version,
        )
        for f in findings
    ]
