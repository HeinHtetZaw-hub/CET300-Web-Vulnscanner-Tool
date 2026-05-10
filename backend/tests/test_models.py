import pytest
from sqlalchemy import select

from app.models.finding import Confidence, Finding, Severity
from app.models.scan import Scan, ScanStatus


@pytest.mark.asyncio
async def test_create_scan(db_session):
    scan = Scan(
        target_url="https://example.com",
        status=ScanStatus.queued,
        config={"modules": ["sqli", "xss"], "crawl_depth": 3},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    assert scan.id is not None
    assert len(scan.id) == 36  # UUID format
    assert scan.status == ScanStatus.queued
    assert scan.total_urls_found == 0
    assert scan.total_findings == 0
    assert scan.created_at is not None
    assert scan.started_at is None
    assert scan.completed_at is None


@pytest.mark.asyncio
async def test_scan_status_transitions(db_session):
    scan = Scan(target_url="https://example.com", status=ScanStatus.queued)
    db_session.add(scan)
    await db_session.commit()

    scan.status = ScanStatus.scanning
    await db_session.commit()
    await db_session.refresh(scan)

    assert scan.status == ScanStatus.scanning


@pytest.mark.asyncio
async def test_create_finding(db_session):
    scan = Scan(target_url="https://example.com", status=ScanStatus.scanning)
    db_session.add(scan)
    await db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        vuln_type="sqli_error",
        severity=Severity.critical,
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        owasp_category="A03",
        owasp_name="Injection",
        affected_url="https://example.com/login",
        affected_parameter="username",
        payload_used="' OR 1=1--",
        evidence_request="POST /login HTTP/1.1\nusername=' OR 1=1--",
        evidence_response="HTTP/1.1 200 OK\nWelcome admin",
        remediation="Use parameterised queries.",
        confidence=Confidence.confirmed,
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)

    assert finding.id is not None
    assert finding.scan_id == scan.id
    assert finding.severity == Severity.critical
    assert finding.cvss_score == 10.0
    assert finding.confidence == Confidence.confirmed


@pytest.mark.asyncio
async def test_cascade_delete(db_session):
    scan = Scan(target_url="https://example.com", status=ScanStatus.queued)
    db_session.add(scan)
    await db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        vuln_type="xss_reflected",
        severity=Severity.medium,
        cvss_score=6.1,
        affected_url="https://example.com/search",
        confidence=Confidence.tentative,
    )
    db_session.add(finding)
    await db_session.commit()

    finding_id = finding.id
    await db_session.delete(scan)
    await db_session.commit()

    result = await db_session.execute(select(Finding).where(Finding.id == finding_id))
    assert result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_scan_status_enum_values(db_session):
    for status in ScanStatus:
        scan = Scan(target_url="https://example.com", status=status)
        db_session.add(scan)
    await db_session.commit()

    result = await db_session.execute(select(Scan))
    scans = result.scalars().all()
    statuses = {s.status for s in scans}
    assert statuses == set(ScanStatus)


@pytest.mark.asyncio
async def test_finding_severity_enum_values(db_session):
    scan = Scan(target_url="https://example.com", status=ScanStatus.completed)
    db_session.add(scan)
    await db_session.commit()

    for sev in Severity:
        finding = Finding(
            scan_id=scan.id,
            vuln_type="misconfig_header",
            severity=sev,
            cvss_score=5.0,
            affected_url="https://example.com/",
            confidence=Confidence.confirmed,
        )
        db_session.add(finding)
    await db_session.commit()

    result = await db_session.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = result.scalars().all()
    assert {f.severity for f in findings} == set(Severity)
