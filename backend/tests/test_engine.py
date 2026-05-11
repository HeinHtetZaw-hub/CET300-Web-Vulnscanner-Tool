"""Tests for the ScanEngine orchestrator.

The Crawler is patched so tests never make real HTTP requests.
All DB operations use the in-memory SQLite session from conftest.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.scanner.crawler import CrawlResult
from app.scanner.engine import ScanEngine, _cancel_events, request_cancel
from app.scanner.modules.base import BaseModule, RawFinding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan(db_session, target_url: str = "http://example.com") -> Scan:
    scan = Scan(target_url=target_url, status=ScanStatus.queued, config={"modules": [], "crawl_depth": 1})
    db_session.add(scan)
    return scan


def _empty_crawl_result() -> CrawlResult:
    return CrawlResult(
        discovered_urls={"http://example.com/"},
        forms=[],
        parameters=[],
    )


def _patch_crawler(crawl_result: CrawlResult | None = None):
    """Context manager: patches Crawler so crawl() returns crawl_result immediately."""
    result = crawl_result or _empty_crawl_result()
    mock_instance = AsyncMock()
    mock_instance.crawl = AsyncMock(return_value=result)
    return patch("app.scanner.engine.Crawler", return_value=mock_instance)


class _OneHitModule(BaseModule):
    """Returns exactly one confirmed SQLi finding — used to test finding persistence."""

    @property
    def name(self) -> str:
        return "OneHit"

    @property
    def vuln_types(self) -> list[str]:
        return ["sqli_error"]

    async def run(self, target_urls, forms, parameters, http_client) -> list[RawFinding]:
        return [
            RawFinding(
                vuln_type="sqli_error",
                affected_url="http://example.com/login",
                affected_parameter="username",
                payload_used="' OR 1=1--",
                evidence_request="POST /login HTTP/1.1\r\n\r\nusername='+OR+1%3D1--",
                evidence_response="You have an error in your SQL syntax",
                confidence="confirmed",
            )
        ]


class _CrashModule(BaseModule):
    """Always raises — engine should swallow the error and continue."""

    @property
    def name(self) -> str:
        return "Crash"

    @property
    def vuln_types(self) -> list[str]:
        return ["sqli_error"]

    async def run(self, target_urls, forms, parameters, http_client) -> list[RawFinding]:
        raise RuntimeError("module exploded")


# ---------------------------------------------------------------------------
# Status lifecycle — no modules
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_lifecycle_no_modules(db_session):
    """Engine without modules goes queued→crawling→scanning→completed."""
    scan = _make_scan(db_session)
    await db_session.commit()
    await db_session.refresh(scan)

    engine = ScanEngine(
        scan_id=scan.id,
        target_url="http://example.com",
        config={"modules": [], "crawl_depth": 1},
        db=db_session,
    )

    with _patch_crawler():
        await engine.run_scan()

    result = await db_session.execute(select(Scan).where(Scan.id == scan.id))
    updated = result.scalar_one()
    assert updated.status == ScanStatus.completed
    assert updated.started_at is not None
    assert updated.completed_at is not None
    assert updated.total_urls_found == 1
    assert updated.total_findings == 0


# ---------------------------------------------------------------------------
# Finding persistence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_finding_is_saved_with_cvss_and_owasp(db_session):
    """A module's RawFinding is persisted with CVSS score and OWASP fields."""
    scan = _make_scan(db_session)
    await db_session.commit()
    await db_session.refresh(scan)

    engine = ScanEngine(
        scan_id=scan.id,
        target_url="http://example.com",
        config={"modules": [], "crawl_depth": 1},
        db=db_session,
    )
    engine._modules = [_OneHitModule()]

    with _patch_crawler():
        await engine.run_scan()

    findings_result = await db_session.execute(
        select(Finding).where(Finding.scan_id == scan.id)
    )
    findings = findings_result.scalars().all()
    assert len(findings) == 1

    f = findings[0]
    assert f.vuln_type == "sqli_error"
    assert f.cvss_score > 0.0
    assert f.owasp_category == "A03"
    assert f.owasp_name == "Injection"
    assert "parameterised" in (f.remediation or "")
    assert f.confidence == "confirmed"
    assert f.affected_url == "http://example.com/login"
    assert f.affected_parameter == "username"

    scan_result = await db_session.execute(select(Scan).where(Scan.id == scan.id))
    updated_scan = scan_result.scalar_one()
    assert updated_scan.total_findings == 1
    assert updated_scan.status == ScanStatus.completed


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cancellation_after_crawl(db_session):
    """Setting the cancel event before run_scan is called stops the engine after the crawl."""
    scan = _make_scan(db_session)
    await db_session.commit()
    await db_session.refresh(scan)

    engine = ScanEngine(
        scan_id=scan.id,
        target_url="http://example.com",
        config={"modules": [], "crawl_depth": 1},
        db=db_session,
    )
    engine._cancel_event.set()  # signal cancellation before any work starts

    with _patch_crawler():
        await engine.run_scan()

    result = await db_session.execute(select(Scan).where(Scan.id == scan.id))
    updated = result.scalar_one()
    assert updated.status == ScanStatus.cancelled


@pytest.mark.asyncio
async def test_request_cancel_sets_event(db_session):
    """request_cancel() signals the engine's cancel event."""
    scan = _make_scan(db_session)
    await db_session.commit()
    await db_session.refresh(scan)

    engine = ScanEngine(
        scan_id=scan.id,
        target_url="http://example.com",
        config={"modules": [], "crawl_depth": 1},
        db=db_session,
    )
    assert not engine._cancel_event.is_set()

    request_cancel(scan.id)
    assert engine._cancel_event.is_set()

    # Clean up: engine never ran, so the event is still in _cancel_events
    _cancel_events.pop(scan.id, None)


# ---------------------------------------------------------------------------
# Module exception resilience
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_crashing_module_does_not_fail_scan(db_session):
    """A module that raises should be skipped; the scan still completes."""
    scan = _make_scan(db_session)
    await db_session.commit()
    await db_session.refresh(scan)

    engine = ScanEngine(
        scan_id=scan.id,
        target_url="http://example.com",
        config={"modules": [], "crawl_depth": 1},
        db=db_session,
    )
    engine._modules = [_CrashModule()]

    with _patch_crawler():
        await engine.run_scan()

    result = await db_session.execute(select(Scan).where(Scan.id == scan.id))
    updated = result.scalar_one()
    assert updated.status == ScanStatus.completed
    assert updated.total_findings == 0


# ---------------------------------------------------------------------------
# Unknown / unimplemented modules
# ---------------------------------------------------------------------------

def test_unknown_module_name_is_skipped(db_session):
    """A module name not in _KNOWN_MODULES is ignored without raising."""
    engine = ScanEngine(
        scan_id="fake-id",
        target_url="http://example.com",
        config={"modules": ["nonexistent_module"], "crawl_depth": 1},
        db=db_session,
    )
    assert engine._modules == []
    _cancel_events.pop("fake-id", None)


def test_unimplemented_module_is_skipped(db_session):
    """A module in _KNOWN_MODULES whose file doesn't exist yet is skipped gracefully."""
    engine = ScanEngine(
        scan_id="fake-id-2",
        target_url="http://example.com",
        config={"modules": ["sqli"], "crawl_depth": 1},
        db=db_session,
    )
    # sqli module not implemented yet → empty list
    assert engine._modules == []
    _cancel_events.pop("fake-id-2", None)


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_progress_callback_is_called(db_session):
    """on_progress callback receives at least the 'completed' event."""
    scan = _make_scan(db_session)
    await db_session.commit()
    await db_session.refresh(scan)

    events: list[tuple[str, int, int]] = []

    engine = ScanEngine(
        scan_id=scan.id,
        target_url="http://example.com",
        config={"modules": [], "crawl_depth": 1},
        db=db_session,
        on_progress=lambda phase, cur, tot: events.append((phase, cur, tot)),
    )

    with _patch_crawler():
        await engine.run_scan()

    phases = [e[0] for e in events]
    assert "completed" in phases


# ---------------------------------------------------------------------------
# Cancel event cleanup
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cancel_event_removed_after_scan(db_session):
    """_cancel_events is cleaned up after run_scan completes."""
    scan = _make_scan(db_session)
    await db_session.commit()
    await db_session.refresh(scan)

    engine = ScanEngine(
        scan_id=scan.id,
        target_url="http://example.com",
        config={"modules": [], "crawl_depth": 1},
        db=db_session,
    )
    assert scan.id in _cancel_events

    with _patch_crawler():
        await engine.run_scan()

    assert scan.id not in _cancel_events
