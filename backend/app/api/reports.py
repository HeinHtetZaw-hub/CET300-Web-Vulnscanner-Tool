from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import Scan

router = APIRouter(prefix="/scans/{scan_id}/report", tags=["reports"])


@router.get("/pdf")
async def download_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _require_completed_scan(scan_id, db)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="PDF report generation is not yet implemented.",
    )


@router.get("/json")
async def download_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _require_completed_scan(scan_id, db)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="JSON report export is not yet implemented.",
    )


async def _require_completed_scan(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan
