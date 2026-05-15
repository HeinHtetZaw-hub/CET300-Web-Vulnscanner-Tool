import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.reporting.pdf_generator import generate_pdf

router = APIRouter(prefix="/scans/{scan_id}/report", tags=["reports"])


@router.get("/pdf")
async def download_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan, findings = await _get_scan_and_findings(scan_id, db)
    pdf_bytes = await generate_pdf(scan, findings)
    safe_id = scan_id[:8]
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="vulnscan_{safe_id}.pdf"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@router.get("/json")
async def download_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan, findings = await _get_scan_and_findings(scan_id, db)

    def _dt(dt: datetime | None) -> str | None:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    payload = {
        "scan": {
            "id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status.value,
            "started_at": _dt(scan.started_at),
            "completed_at": _dt(scan.completed_at),
            "total_urls_found": scan.total_urls_found,
            "total_findings": scan.total_findings,
            "config": scan.config,
        },
        "summary": {
            "critical": sev_counts.get("critical", 0),
            "high":     sev_counts.get("high", 0),
            "medium":   sev_counts.get("medium", 0),
            "low":      sev_counts.get("low", 0),
            "info":     sev_counts.get("info", 0),
        },
        "findings": [
            {
                "id": f.id,
                "vuln_type": f.vuln_type,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "owasp_category": f.owasp_category,
                "owasp_name": f.owasp_name,
                "affected_url": f.affected_url,
                "affected_parameter": f.affected_parameter,
                "payload_used": f.payload_used,
                "evidence_request": f.evidence_request,
                "evidence_response": f.evidence_response,
                "remediation": f.remediation,
                "confidence": f.confidence.value,
                "created_at": _dt(f.created_at),
            }
            for f in sorted(findings, key=lambda x: x.cvss_score, reverse=True)
        ],
    }

    json_bytes = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    safe_id = scan_id[:8]
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="vulnscan_{safe_id}.json"',
            "Content-Length": str(len(json_bytes)),
        },
    )


async def _get_scan_and_findings(
    scan_id: str, db: AsyncSession
) -> tuple[Scan, list[Finding]]:
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Scan not found.")
    if scan.status != ScanStatus.completed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Reports are only available for completed scans. "
                   f"Current status: {scan.status.value}.",
        )

    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.cvss_score.desc())
    )
    findings = list(findings_result.scalars().all())
    return scan, findings
