import pytest

from app.models.finding import Confidence, Finding, Severity


async def _make_scan(client):
    r = await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": True},
    )
    return r.json()["id"]


async def _seed_finding(db_session, scan_id: str, **overrides) -> Finding:
    defaults = dict(
        scan_id=scan_id,
        vuln_type="sqli_error",
        severity=Severity.critical,
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        owasp_category="A03",
        owasp_name="Injection",
        affected_url="https://example.com/login",
        affected_parameter="username",
        payload_used="' OR 1=1--",
        evidence_request="POST /login HTTP/1.1",
        evidence_response="HTTP/1.1 200 OK",
        remediation="Use parameterised queries.",
        confidence=Confidence.confirmed,
    )
    defaults.update(overrides)
    finding = Finding(**defaults)
    db_session.add(finding)
    await db_session.commit()
    return finding


# ── GET /scans/{id}/findings ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_findings_empty(client):
    scan_id = await _make_scan(client)
    response = await client.get(f"/api/v1/scans/{scan_id}/findings")
    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": []}


@pytest.mark.asyncio
async def test_list_findings_returns_findings(client, db_session):
    scan_id = await _make_scan(client)
    await _seed_finding(db_session, scan_id)
    await _seed_finding(db_session, scan_id, vuln_type="xss_reflected", severity=Severity.medium, cvss_score=6.1)

    response = await client.get(f"/api/v1/scans/{scan_id}/findings")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    # default sort is cvss_score desc — critical (10.0) comes first
    assert data["items"][0]["cvss_score"] == 10.0


@pytest.mark.asyncio
async def test_list_findings_filter_by_severity(client, db_session):
    scan_id = await _make_scan(client)
    await _seed_finding(db_session, scan_id, severity=Severity.critical, cvss_score=10.0)
    await _seed_finding(db_session, scan_id, severity=Severity.low, cvss_score=3.1)

    response = await client.get(f"/api/v1/scans/{scan_id}/findings?severity=critical")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_list_findings_filter_by_owasp(client, db_session):
    scan_id = await _make_scan(client)
    await _seed_finding(db_session, scan_id, owasp_category="A03")
    await _seed_finding(db_session, scan_id, owasp_category="A01")

    response = await client.get(f"/api/v1/scans/{scan_id}/findings?owasp_category=A01")
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["owasp_category"] == "A01"


@pytest.mark.asyncio
async def test_list_findings_sort_asc(client, db_session):
    scan_id = await _make_scan(client)
    await _seed_finding(db_session, scan_id, cvss_score=10.0)
    await _seed_finding(db_session, scan_id, cvss_score=3.1, severity=Severity.low)

    response = await client.get(f"/api/v1/scans/{scan_id}/findings?sort_by=cvss_score&order=asc")
    items = response.json()["items"]
    assert items[0]["cvss_score"] == 3.1


@pytest.mark.asyncio
async def test_list_findings_404_for_unknown_scan(client):
    response = await client.get("/api/v1/scans/no-such-scan/findings")
    assert response.status_code == 404


# ── GET /scans/{id}/findings/{fid} ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_finding_returns_evidence_fields(client, db_session):
    scan_id = await _make_scan(client)
    finding = await _seed_finding(db_session, scan_id)

    response = await client.get(f"/api/v1/scans/{scan_id}/findings/{finding.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == finding.id
    assert data["payload_used"] == "' OR 1=1--"
    assert data["evidence_request"] == "POST /login HTTP/1.1"
    assert data["remediation"] == "Use parameterised queries."


@pytest.mark.asyncio
async def test_get_finding_404_for_unknown_id(client):
    scan_id = await _make_scan(client)
    response = await client.get(f"/api/v1/scans/{scan_id}/findings/no-such-finding")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_finding_404_for_wrong_scan(client, db_session):
    scan_id_a = await _make_scan(client)
    scan_id_b = await _make_scan(client)
    finding = await _seed_finding(db_session, scan_id_a)

    # finding belongs to scan A — should 404 when looked up under scan B
    response = await client.get(f"/api/v1/scans/{scan_id_b}/findings/{finding.id}")
    assert response.status_code == 404
