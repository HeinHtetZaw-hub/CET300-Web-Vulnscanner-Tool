

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, get_db
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.scanner.engine import ScanEngine, request_cancel
from app.schemas.scan import (
    DEFAULT_CONFIG,
    ScanCreate,
    ScanListResponse,
    ScanProgress,
    ScanResponse,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    config = body.config or DEFAULT_CONFIG
    scan = Scan(
        target_url=str(body.target_url),
        status=ScanStatus.queued,
        config=config,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    background_tasks.add_task(_run_scan_background, scan.id, str(body.target_url), config)
    return scan


async def _run_scan_background(scan_id: str, target_url: str, config: dict) -> None:
    """Background task: creates its own DB session and drives the scan engine."""
    async with AsyncSessionLocal() as session:
        engine = ScanEngine(
            scan_id=scan_id,
            target_url=target_url,
            config=config,
            db=session,
        )
        await engine.run_scan()


@router.get("", response_model=ScanListResponse)
async def list_scans(
    scan_status: ScanStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    query = select(Scan)
    if scan_status is not None:
        query = query.where(Scan.status == scan_status)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    )
    scans = result.scalars().all()
    return ScanListResponse(total=total, items=list(scans))


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)
    return scan


@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)

    sev_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    )
    findings_by_severity = {row[0].value: row[1] for row in sev_result.all()}

    return ScanProgress(
        id=scan.id,
        status=scan.status,
        total_urls_found=scan.total_urls_found,
        total_findings=scan.total_findings,
        current_module=scan.current_module,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        findings_by_severity=findings_by_severity,
    )


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)
    if scan.status in (ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is already {scan.status.value} and cannot be cancelled.",
        )
    request_cancel(scan_id)
    scan.status = ScanStatus.cancelled
    await db.commit()
    await db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)
    await db.delete(scan)
    await db.commit()


async def _get_scan_or_404(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan
