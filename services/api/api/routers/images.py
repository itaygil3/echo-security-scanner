from fastapi import APIRouter, HTTPException, Request, status

from api.dependencies import SeverityFilter
from api.schemas import ImageSummary, ImageVulnerability
from echo_common.db.tables import image_cves
from echo_common.enums import Severity
from echo_common.models import ImageRef

router = APIRouter(prefix="/api/images", tags=["images"])


@router.get("", response_model=list[ImageSummary])
async def list_images(request: Request) -> list[ImageSummary]:
    """All scanned images with the number of distinct CVEs per severity."""
    images = await request.app.state.images.list_all()
    counts = await request.app.state.image_cves.count_cves_by_severity()
    summaries = []
    for image in images:
        by_severity = {severity.name: counts.get(image.id, {}).get(severity, 0) for severity in reversed(Severity)}
        summaries.append(
            ImageSummary(
                name=image.name,
                tag=image.tag,
                scan_status=image.scan_status,
                last_scan_at=image.last_scan_at,
                last_error=image.last_error,
                severity_counts={**by_severity, "total": sum(by_severity.values())},
            )
        )
    return summaries


@router.get("/{image_name:path}/{tag}/cves", response_model=list[ImageVulnerability])
async def image_cves_list(
    request: Request,
    image_name: str,
    tag: str,
    severity: SeverityFilter,
) -> list[ImageVulnerability]:
    """CVEs found in one image (with package details), optionally filtered by severity."""
    image = await request.app.state.images.get_by_ref(ImageRef(name=image_name, tag=tag))
    if image is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Image {image_name}:{tag} not found")

    where = [image_cves.c.image_id == image.id]
    if severity is not None:
        where.append(image_cves.c.severity == severity)
    findings = await request.app.state.image_cves.find_details(*where)
    return [
        ImageVulnerability(
            cve_id=f.cve_id,
            severity=f.severity.name,
            title=f.cve_title,
            description=f.cve_description,
            primary_url=f.cve_primary_url,
            package_name=f.package_name,
            package_type=f.package_type,
            installed_version=f.installed_version,
            fixed_version=f.fixed_version,
        )
        for f in findings
    ]
