from datetime import datetime

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, field_validator

from app.models.scan import ScanStatus

DEFAULT_CONFIG = {
    "modules": ["sqli", "xss_reflected", "xss_stored", "xss_dom", "bac", "misconfig", "exposure"],
    "crawl_depth": 3,
}


class ScanCreate(BaseModel):
    target_url: AnyHttpUrl
    authorisation_confirmed: bool
    config: dict | None = None

    @field_validator("authorisation_confirmed")
    @classmethod
    def must_confirm_authorisation(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm you have authorisation to scan this target. "
                "Scanning without permission may violate the Computer Misuse Act 1990 "
                "and Myanmar Electronic Transactions Law 2004."
            )
        return v


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_urls_found: int
    total_findings: int
    config: dict | None = None
    created_at: datetime


class ScanListResponse(BaseModel):
    total: int
    items: list[ScanResponse]


class ScanProgress(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: ScanStatus
    total_urls_found: int
    total_findings: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
