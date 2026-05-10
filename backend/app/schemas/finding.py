from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.finding import Confidence, Severity


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    vuln_type: str
    severity: Severity
    cvss_score: float
    cvss_vector: str | None = None
    owasp_category: str | None = None
    owasp_name: str | None = None
    affected_url: str
    affected_parameter: str | None = None
    confidence: Confidence
    created_at: datetime


class FindingDetail(FindingResponse):
    payload_used: str | None = None
    evidence_request: str | None = None
    evidence_response: str | None = None
    remediation: str | None = None


class FindingListResponse(BaseModel):
    total: int
    items: list[FindingResponse]
