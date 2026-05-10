from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.finding import Finding, Severity
from app.models.scan import Scan
from app.schemas.finding import FindingDetail, FindingListResponse

router = APIRouter(prefix="/scans/{scan_id}/findings", tags=["findings"])

_SORTABLE_COLUMNS = {
    "cvss_score": Finding.cvss_score,
    "severity": Finding.severity,
    "created_at": Finding.created_at,
}


@router.get("", response_model=FindingListResponse)
async def list_findings(
    scan_id: str,
    severity: Severity | None = Query(default=None),
    owasp_category: str | None = Query(default=None),
    sort_by: Literal["cvss_score", "severity", "created_at"] = Query(default="cvss_score"),
    order: Literal["asc", "desc"] = Query(default="desc"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    await _require_scan(scan_id, db)

    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if owasp_category is not None:
        query = query.where(Finding.owasp_category == owasp_category)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    col = _SORTABLE_COLUMNS[sort_by]
    col = col.desc() if order == "desc" else col.asc()
    result = await db.execute(query.order_by(col).offset(offset).limit(limit))
    findings = result.scalars().all()
    return FindingListResponse(total=total, items=list(findings))


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    await _require_scan(scan_id, db)

    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return finding


async def _require_scan(scan_id: str, db: AsyncSession) -> None:
    result = await db.execute(select(Scan.id).where(Scan.id == scan_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
