from fastapi import APIRouter

from app.api import findings, reports, scans

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
