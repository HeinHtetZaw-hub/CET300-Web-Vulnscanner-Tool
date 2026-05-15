"""Integration tests: full end-to-end scan against DVWA.

These tests require two services to be running locally:

    DVWA (target):
        docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
        # First run only: visit http://localhost:8080/setup.php → Create / Reset Database
        # Then login at http://localhost:8080 (admin / password) and set security to Low

    VulnScanner backend:
        cd backend && uvicorn app.main:app --port 8000
        OR: docker compose up --build -d backend

    Run integration tests:
        pytest -v -m integration tests/test_integration_dvwa.py

    Exclude integration tests (unit tests only):
        pytest -v -m "not integration"

Note: DVWA runs on 127.0.0.1 (loopback). The private-IP guard in url_validator.py
is defined but not yet wired into the scan creation endpoint, so scanning localhost
is permitted during development and testing.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DVWA_URL    = "http://localhost:8080"
BACKEND_URL = "http://localhost:8000"
API_BASE    = f"{BACKEND_URL}/api/v1"

POLL_INTERVAL  = 5     # seconds between status polls
SCAN_TIMEOUT   = 600   # 10 minutes – generous for a full crawl + all modules

# All tests in this module require external services
pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# CVSS ground-truth (matches scoring/vectors.py)
# ---------------------------------------------------------------------------

EXPECTED_CVSS: dict[str, tuple[float, str, str]] = {
    "sqli_error":         (10.0, "critical", "A03"),
    "sqli_blind_boolean": (10.0, "critical", "A03"),
    "sqli_blind_time":    (10.0, "critical", "A03"),
    "xss_reflected":      (6.1,  "medium",   "A03"),
    "xss_stored":         (6.4,  "medium",   "A03"),
    "xss_dom":            (6.1,  "medium",   "A03"),
    "idor":               (8.1,  "high",     "A01"),
    "ssrf":               (8.6,  "high",     "A01"),
    "misconfig_header":   (5.3,  "medium",   "A05"),
    "misconfig_file":     (7.5,  "high",     "A05"),
    "data_exposure":      (7.5,  "high",     "A02"),
}

# ---------------------------------------------------------------------------
# Helper coroutines (shared by all tests)
# ---------------------------------------------------------------------------

async def _service_up(url: str, timeout: float = 3.0) -> bool:
    """Return True if the URL responds with a non-5xx status code."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            return r.status_code < 500
    except Exception:
        return False


async def _start_scan(
    target: str = DVWA_URL,
    modules: list[str] | None = None,
    depth: int = 2,
) -> str:
    """POST /scans and return the new scan_id."""
    if modules is None:
        modules = [
            "sqli", "xss_reflected", "xss_stored",
            "bac", "misconfig", "exposure",
        ]
    payload = {
        "target_url": target,
        "authorisation_confirmed": True,
        "config": {"modules": modules, "crawl_depth": depth},
    }
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(f"{API_BASE}/scans", json=payload)
    assert r.status_code == 201, (
        f"Expected 201 creating scan, got {r.status_code}: {r.text}"
    )
    return r.json()["id"]


async def _wait_for_scan(scan_id: str, timeout: int = SCAN_TIMEOUT) -> dict[str, Any]:
    """Poll GET /scans/{id} until the scan reaches a terminal status."""
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=15.0) as c:
        while time.monotonic() < deadline:
            r = await c.get(f"{API_BASE}/scans/{scan_id}")
            assert r.status_code == 200, f"Unexpected status {r.status_code} polling scan"
            data = r.json()
            if data["status"] in ("completed", "failed", "cancelled"):
                return data
            await asyncio.sleep(POLL_INTERVAL)
    raise TimeoutError(
        f"Scan {scan_id} did not complete within {timeout}s. "
        "Increase SCAN_TIMEOUT or reduce crawl depth."
    )


async def _get_findings(
    scan_id: str, limit: int = 200, **params: Any
) -> list[dict[str, Any]]:
    """Return all findings for a scan, optionally filtered."""
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"{API_BASE}/scans/{scan_id}/findings",
            params={"limit": limit, **params},
        )
    assert r.status_code == 200
    return r.json()["items"]


async def _configure_dvwa() -> None:
    """Login to DVWA and set security level to Low (best-effort; skip on error)."""
    try:
        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=True
        ) as c:
            await c.get(f"{DVWA_URL}/login.php")
            await c.post(
                f"{DVWA_URL}/login.php",
                data={"username": "admin", "password": "password", "Login": "Login"},
            )
            await c.post(
                f"{DVWA_URL}/security.php",
                data={"security": "low", "seclev_submit": "Submit"},
            )
    except Exception:
        pass  # Non-fatal; some DVWA versions handle this differently


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def require_services() -> None:
    """Skip the entire module if DVWA or the backend is not reachable."""
    dvwa_ok    = await _service_up(f"{DVWA_URL}/login.php")
    backend_ok = await _service_up(f"{BACKEND_URL}/health")

    if not dvwa_ok:
        pytest.skip(
            "DVWA not reachable at http://localhost:8080. "
            "Start with: docker run -d -p 8080:80 vulnerables/web-dvwa"
        )
    if not backend_ok:
        pytest.skip(
            "Backend not reachable at http://localhost:8000. "
            "Start with: cd backend && uvicorn app.main:app --port 8000"
        )

    await _configure_dvwa()


# ---------------------------------------------------------------------------
# 1. Sanity — backend health check
# ---------------------------------------------------------------------------

async def test_backend_health_returns_ok() -> None:
    """GET /health must return { status: 'ok' }."""
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.get(f"{BACKEND_URL}/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


# ---------------------------------------------------------------------------
# 2. Misconfig module — missing security headers
# ---------------------------------------------------------------------------

async def test_misconfig_detects_missing_headers() -> None:
    """DVWA does not set security headers; the misconfig module must find them."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    scan = await _wait_for_scan(scan_id)

    assert scan["status"] == "completed", (
        f"Scan ended with status '{scan['status']}' instead of 'completed'"
    )

    findings = await _get_findings(scan_id)
    header_findings = [f for f in findings if f["vuln_type"] == "misconfig_header"]

    assert len(header_findings) > 0, (
        "Expected at least one missing-header finding against DVWA. "
        "DVWA does not send Content-Security-Policy or other security headers."
    )


async def test_misconfig_header_cvss_score() -> None:
    """All misconfig_header findings must have CVSS score == 5.3 and category A05."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    scan = await _wait_for_scan(scan_id)
    assert scan["status"] == "completed"

    findings = await _get_findings(scan_id)
    header_findings = [f for f in findings if f["vuln_type"] == "misconfig_header"]

    for f in header_findings:
        assert f["cvss_score"] == 5.3, (
            f"Expected CVSS 5.3 for misconfig_header, got {f['cvss_score']}"
        )
        assert f["severity"] == "medium"
        assert f["owasp_category"] == "A05"
        assert f["owasp_name"] is not None


# ---------------------------------------------------------------------------
# 3. SQL injection module
# ---------------------------------------------------------------------------

async def test_sqli_scan_completes_successfully() -> None:
    """SQLi scan against DVWA must reach 'completed' without crashing."""
    scan_id = await _start_scan(modules=["sqli"], depth=2)
    scan = await _wait_for_scan(scan_id)
    assert scan["status"] == "completed", (
        f"SQLi scan failed with status '{scan['status']}'"
    )
    assert scan["total_urls_found"] > 0, "Crawler should discover at least one URL"


async def test_sqli_findings_have_correct_cvss() -> None:
    """Any SQLi findings must have CVSS 10.0 (Critical) and OWASP A03."""
    scan_id = await _start_scan(modules=["sqli"], depth=2)
    scan = await _wait_for_scan(scan_id)
    assert scan["status"] == "completed"

    findings = await _get_findings(scan_id)
    sqli_findings = [
        f for f in findings if f["vuln_type"].startswith("sqli_")
    ]

    for f in sqli_findings:
        assert f["cvss_score"] == 10.0, (
            f"{f['vuln_type']}: expected CVSS 10.0, got {f['cvss_score']}"
        )
        assert f["severity"] == "critical"
        assert f["owasp_category"] == "A03"
        assert f["cvss_vector"].startswith("CVSS:3.1/")


# ---------------------------------------------------------------------------
# 4. Reflected XSS module
# ---------------------------------------------------------------------------

async def test_xss_reflected_scan_completes() -> None:
    """Reflected XSS scan against DVWA must reach 'completed'."""
    scan_id = await _start_scan(modules=["xss_reflected"], depth=2)
    scan = await _wait_for_scan(scan_id)
    assert scan["status"] == "completed", (
        f"XSS-reflected scan ended: '{scan['status']}'"
    )


async def test_xss_reflected_findings_have_correct_cvss() -> None:
    """Any xss_reflected findings must have CVSS 6.1 (Medium) and OWASP A03."""
    scan_id = await _start_scan(modules=["xss_reflected"], depth=2)
    scan = await _wait_for_scan(scan_id)
    assert scan["status"] == "completed"

    findings = await _get_findings(scan_id)
    xss_findings = [f for f in findings if f["vuln_type"] == "xss_reflected"]

    for f in xss_findings:
        assert f["cvss_score"] == 6.1
        assert f["severity"] == "medium"
        assert f["owasp_category"] == "A03"


# ---------------------------------------------------------------------------
# 5. Full scan — all modules
# ---------------------------------------------------------------------------

async def test_full_scan_completes_and_finds_vulnerabilities() -> None:
    """
    Full scan (all modules, depth 2) must complete and detect at least
    misconfig_header findings (guaranteed since DVWA lacks security headers).
    """
    scan_id = await _start_scan(
        modules=["sqli", "xss_reflected", "xss_stored", "bac", "misconfig", "exposure"],
        depth=2,
    )
    scan = await _wait_for_scan(scan_id)

    assert scan["status"] == "completed", (
        f"Full scan did not complete: '{scan['status']}'"
    )
    assert scan["total_urls_found"] > 0
    assert scan["total_findings"] > 0, (
        "Full scan should detect at least the missing security headers"
    )


async def test_full_scan_progress_endpoint() -> None:
    """GET /scans/{id}/progress must return findings_by_severity breakdown."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    await _wait_for_scan(scan_id)

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(f"{API_BASE}/scans/{scan_id}/progress")
    assert r.status_code == 200
    data = r.json()

    assert "findings_by_severity" in data
    assert isinstance(data["findings_by_severity"], dict)
    assert "current_module" in data
    assert data["status"] == "completed"


async def test_all_findings_have_required_fields() -> None:
    """Every finding returned by the API must have mandatory fields populated."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    await _wait_for_scan(scan_id)
    findings = await _get_findings(scan_id)

    required = [
        "id", "scan_id", "vuln_type", "severity", "cvss_score",
        "owasp_category", "affected_url", "confidence",
    ]
    for f in findings:
        for field in required:
            assert field in f and f[field] is not None, (
                f"Finding {f.get('id')} missing required field '{field}'"
            )


async def test_cvss_scores_match_expected_values() -> None:
    """CVSS scores for known vuln_types must exactly match the pre-defined vectors."""
    scan_id = await _start_scan(modules=["misconfig", "sqli", "xss_reflected"], depth=2)
    await _wait_for_scan(scan_id)
    findings = await _get_findings(scan_id)

    for f in findings:
        if f["vuln_type"] not in EXPECTED_CVSS:
            continue
        expected_score, expected_sev, expected_owasp = EXPECTED_CVSS[f["vuln_type"]]
        assert f["cvss_score"] == expected_score, (
            f"{f['vuln_type']}: CVSS {f['cvss_score']} != expected {expected_score}"
        )
        assert f["severity"] == expected_sev, (
            f"{f['vuln_type']}: severity '{f['severity']}' != expected '{expected_sev}'"
        )
        assert f["owasp_category"] == expected_owasp, (
            f"{f['vuln_type']}: OWASP '{f['owasp_category']}' != expected '{expected_owasp}'"
        )


async def test_findings_owasp_categories_are_valid() -> None:
    """All findings must have a recognised OWASP Top 10 category (A01–A10)."""
    valid_categories = {f"A{n:02d}" for n in range(1, 11)}
    scan_id = await _start_scan(modules=["misconfig", "sqli"], depth=1)
    await _wait_for_scan(scan_id)
    findings = await _get_findings(scan_id)

    for f in findings:
        assert f["owasp_category"] in valid_categories, (
            f"vuln_type '{f['vuln_type']}' has unrecognised OWASP "
            f"category '{f['owasp_category']}'"
        )
        assert f["owasp_name"] is not None and len(f["owasp_name"]) > 0


async def test_findings_evidence_is_captured() -> None:
    """Full finding detail must include payload_used and HTTP evidence."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    await _wait_for_scan(scan_id)
    findings = await _get_findings(scan_id)

    if not findings:
        pytest.skip("No findings to check evidence for")

    fid = findings[0]["id"]
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(f"{API_BASE}/scans/{scan_id}/findings/{fid}")
    assert r.status_code == 200
    detail = r.json()

    # evidence_request is populated for header-based findings (the HEAD request)
    assert "evidence_request" in detail
    assert "evidence_response" in detail
    assert "remediation" in detail and detail["remediation"]


# ---------------------------------------------------------------------------
# 6. PDF report
# ---------------------------------------------------------------------------

async def test_pdf_report_generates_successfully() -> None:
    """GET /report/pdf must return a valid PDF binary for a completed scan."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    scan = await _wait_for_scan(scan_id)
    assert scan["status"] == "completed"

    async with httpx.AsyncClient(timeout=60.0) as c:
        r = await c.get(f"{API_BASE}/scans/{scan_id}/report/pdf")

    assert r.status_code == 200, f"Expected 200 for PDF, got {r.status_code}: {r.text[:200]}"
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF", "Response body does not start with PDF magic bytes"
    assert b"%%EOF" in r.content, "PDF is missing %%EOF marker"
    assert len(r.content) > 5_000, (
        f"PDF is suspiciously small ({len(r.content)} bytes)"
    )


async def test_pdf_report_unavailable_for_running_scan() -> None:
    """GET /report/pdf must return 409 Conflict if the scan is not yet completed."""
    scan_id = await _start_scan(modules=["sqli", "xss_reflected"], depth=3)
    # Don't wait — check immediately after creating (scan is queued/crawling)
    await asyncio.sleep(1)

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(f"{API_BASE}/scans/{scan_id}/report/pdf")

    # Clean up: cancel the scan we just started
    async with httpx.AsyncClient(timeout=10.0) as c:
        await c.post(f"{API_BASE}/scans/{scan_id}/cancel")

    assert r.status_code in (409, 200), (
        f"Expected 409 (not completed) or 200 (already done), got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# 7. JSON export
# ---------------------------------------------------------------------------

async def test_json_export_schema() -> None:
    """GET /report/json must return a well-formed JSON export with the correct schema."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    scan = await _wait_for_scan(scan_id)
    assert scan["status"] == "completed"

    async with httpx.AsyncClient(timeout=30.0) as c:
        r = await c.get(f"{API_BASE}/scans/{scan_id}/report/json")

    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]

    data = r.json()

    # Top-level keys
    assert "scan" in data,     "JSON export missing 'scan' key"
    assert "summary" in data,  "JSON export missing 'summary' key"
    assert "findings" in data, "JSON export missing 'findings' key"

    # Scan sub-object
    scan_obj = data["scan"]
    for key in ("id", "target_url", "status", "total_findings"):
        assert key in scan_obj, f"scan object missing '{key}'"
    assert scan_obj["status"] == "completed"
    assert scan_obj["target_url"] == DVWA_URL + "/"

    # Summary sub-object
    for sev in ("critical", "high", "medium", "low"):
        assert sev in data["summary"], f"summary missing '{sev}' key"
        assert isinstance(data["summary"][sev], int)

    # Findings list
    assert isinstance(data["findings"], list)
    for f in data["findings"]:
        for key in ("id", "vuln_type", "severity", "cvss_score",
                    "owasp_category", "affected_url"):
            assert key in f, f"Finding missing '{key}'"
        assert isinstance(f["cvss_score"], (int, float))


async def test_json_export_findings_sorted_by_cvss() -> None:
    """Findings in the JSON export must be sorted by CVSS score descending."""
    scan_id = await _start_scan(modules=["misconfig", "sqli"], depth=2)
    await _wait_for_scan(scan_id)

    async with httpx.AsyncClient(timeout=30.0) as c:
        r = await c.get(f"{API_BASE}/scans/{scan_id}/report/json")
    assert r.status_code == 200

    findings = r.json()["findings"]
    if len(findings) < 2:
        pytest.skip("Not enough findings to verify sort order")

    scores = [f["cvss_score"] for f in findings]
    assert scores == sorted(scores, reverse=True), (
        f"Findings not sorted by CVSS desc: {scores}"
    )


# ---------------------------------------------------------------------------
# 8. Scan lifecycle — cancel and delete
# ---------------------------------------------------------------------------

async def test_cancel_running_scan() -> None:
    """POST /scans/{id}/cancel must stop a running scan and set status to cancelled."""
    # Start a slow scan (many modules, deep crawl) so it's still running when we cancel
    scan_id = await _start_scan(
        modules=["sqli", "xss_reflected", "xss_stored"], depth=3
    )
    await asyncio.sleep(3)  # give the scan a moment to start

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(f"{API_BASE}/scans/{scan_id}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


async def test_delete_scan_removes_findings() -> None:
    """DELETE /scans/{id} must remove the scan and cascade-delete its findings."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    await _wait_for_scan(scan_id)

    async with httpx.AsyncClient(timeout=10.0) as c:
        del_r = await c.delete(f"{API_BASE}/scans/{scan_id}")
        assert del_r.status_code == 204

        get_r = await c.get(f"{API_BASE}/scans/{scan_id}")
        assert get_r.status_code == 404

        findings_r = await c.get(f"{API_BASE}/scans/{scan_id}/findings")
        assert findings_r.status_code == 404


# ---------------------------------------------------------------------------
# 9. Findings filter / sort API
# ---------------------------------------------------------------------------

async def test_findings_filter_by_severity() -> None:
    """GET /findings?severity= must return only findings of the requested severity."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    await _wait_for_scan(scan_id)

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(
            f"{API_BASE}/scans/{scan_id}/findings",
            params={"severity": "medium", "limit": 50},
        )
    assert r.status_code == 200
    for f in r.json()["items"]:
        assert f["severity"] == "medium", (
            f"Filter returned finding with severity '{f['severity']}'"
        )


async def test_findings_filter_by_owasp_category() -> None:
    """GET /findings?owasp_category= must return only findings for that category."""
    scan_id = await _start_scan(modules=["misconfig"], depth=1)
    await _wait_for_scan(scan_id)

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(
            f"{API_BASE}/scans/{scan_id}/findings",
            params={"owasp_category": "A05", "limit": 50},
        )
    assert r.status_code == 200
    for f in r.json()["items"]:
        assert f["owasp_category"] == "A05"


async def test_findings_sort_by_cvss_ascending() -> None:
    """sort_by=cvss_score&order=asc must return findings in ascending CVSS order."""
    scan_id = await _start_scan(modules=["misconfig", "sqli"], depth=2)
    await _wait_for_scan(scan_id)

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(
            f"{API_BASE}/scans/{scan_id}/findings",
            params={"sort_by": "cvss_score", "order": "asc", "limit": 100},
        )
    assert r.status_code == 200
    items = r.json()["items"]
    if len(items) < 2:
        pytest.skip("Not enough findings to verify sort order")

    scores = [f["cvss_score"] for f in items]
    assert scores == sorted(scores), f"Expected ascending order, got: {scores}"
