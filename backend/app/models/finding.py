import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Severity(str, PyEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, PyEnum):
    confirmed = "confirmed"
    tentative = "tentative"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vuln_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        index=True,
    )
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cvss_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    owasp_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    affected_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    affected_parameter: Mapped[str | None] = mapped_column(String(256), nullable=True)
    payload_used: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence, values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=Confidence.tentative,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")  # noqa: F821
