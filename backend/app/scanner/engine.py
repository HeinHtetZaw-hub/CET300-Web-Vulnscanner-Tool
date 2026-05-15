"""Scan engine orchestrator.

Lifecycle: queued → crawling → scanning → completed (or failed / cancelled).
"""
from __future__ import annotations

import asyncio
import importlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.mapping.owasp_mapper import get_remediation, map_to_owasp
from app.models.finding import Confidence, Finding, Severity
from app.models.scan import Scan, ScanStatus
from app.scanner.crawler import Crawler
from app.scanner.modules.base import BaseModule, RawFinding
from app.scoring.cvss_engine import calculate_cvss
from app.utils.http_client import RateLimitedClient

logger = logging.getLogger(__name__)

# Maps config module name → (import_path, class_name) for lazy loading.
# Modules are imported on demand so unimplemented ones are skipped gracefully.
_KNOWN_MODULES: dict[str, tuple[str, str]] = {
    "sqli":          ("app.scanner.modules.sqli",          "SQLiModule"),
    "xss_reflected": ("app.scanner.modules.xss_reflected", "ReflectedXSSModule"),
    "xss_stored":    ("app.scanner.modules.xss_stored",    "StoredXSSModule"),
    "xss_dom":       ("app.scanner.modules.xss_dom",       "DOMXSSModule"),
    "bac":           ("app.scanner.modules.bac",           "BACModule"),
    "misconfig":     ("app.scanner.modules.misconfig",     "MisconfigModule"),
    "exposure":      ("app.scanner.modules.exposure",      "ExposureModule"),
}

# Per-scan cancellation signals. Engine registers on init, removes on finish.
_cancel_events: dict[str, asyncio.Event] = {}


def request_cancel(scan_id: str) -> None:
    """Signal a running ScanEngine to stop at the next safe checkpoint.

    Called by the cancel API endpoint. No-op if the scan is not running.
    """
    event = _cancel_events.get(scan_id)
    if event:
        event.set()


class ScanEngine:
    """Orchestrates crawling, detection, scoring, and persistence for one scan.

    Args:
        scan_id:     UUID string of the Scan row to drive.
        target_url:  Validated target URL.
        config:      Scan config dict — keys: 'modules' (list[str]), 'crawl_depth' (int).
        db:          Async SQLAlchemy session. The caller is responsible for its lifecycle.
        on_progress: Optional callback ``fn(phase, current, total)`` for live updates.
    """

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        config: dict,
        db: AsyncSession,
        on_progress: Callable[[str, int, int], None] | None = None,
    ) -> None:
        self._scan_id = scan_id
        self._target_url = target_url
        self._config = config
        self._db = db
        self._on_progress = on_progress

        self._cancel_event = asyncio.Event()
        _cancel_events[scan_id] = self._cancel_event

        self._modules: list[BaseModule] = self._load_modules()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run_scan(self) -> None:
        """Execute the full scan lifecycle. Always cleans up the cancel event."""
        try:
            await self._run()
        except Exception:
            logger.exception("Scan %s: unrecoverable error", self._scan_id)
            await self._mark_failed()
        finally:
            _cancel_events.pop(self._scan_id, None)

    # ------------------------------------------------------------------
    # Lifecycle phases
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        await self._update_scan(
            status=ScanStatus.crawling,
            started_at=datetime.now(UTC),
            current_module=None,
        )

        crawl_depth = self._config.get("crawl_depth", 3)
        max_pages = self._config.get("max_pages", 500)

        async with RateLimitedClient() as client:
            crawler = Crawler(
                base_url=self._target_url,
                http_client=client,
                max_depth=crawl_depth,
                max_pages=max_pages,
                on_progress=lambda crawled, total: self._emit("crawling", crawled, total),
            )
            crawl_result = await crawler.crawl()

        if self._cancel_event.is_set():
            await self._update_scan(status=ScanStatus.cancelled)
            return

        await self._update_scan(
            status=ScanStatus.scanning,
            total_urls_found=len(crawl_result.discovered_urls),
        )

        total_findings = 0
        for idx, module in enumerate(self._modules):
            if self._cancel_event.is_set():
                await self._update_scan(status=ScanStatus.cancelled, current_module=None)
                return

            await self._update_scan(current_module=module.name)
            self._emit("scanning", idx, len(self._modules))
            logger.info("Scan %s: running module '%s'", self._scan_id, module.name)

            async with RateLimitedClient() as client:
                try:
                    raw_findings = await module.run(
                        target_urls=crawl_result.discovered_urls,
                        forms=crawl_result.forms,
                        parameters=crawl_result.parameters,
                        http_client=client,
                    )
                except Exception:
                    logger.exception(
                        "Scan %s: module '%s' raised — skipping",
                        self._scan_id, module.name,
                    )
                    continue

            for raw in raw_findings:
                await self._save_finding(raw)
                total_findings += 1
                await self._update_scan(total_findings=total_findings)

        await self._update_scan(
            status=ScanStatus.completed,
            completed_at=datetime.now(UTC),
            total_findings=total_findings,
            current_module=None,
        )
        self._emit("completed", total_findings, total_findings)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _save_finding(self, raw: RawFinding) -> None:
        cvss_score, severity_label, cvss_vector = calculate_cvss(raw.vuln_type)
        owasp_category, owasp_name = map_to_owasp(raw.vuln_type)
        remediation = get_remediation(raw.vuln_type)

        try:
            severity = Severity(severity_label.lower())
        except ValueError:
            severity = Severity.info

        finding = Finding(
            scan_id=self._scan_id,
            vuln_type=raw.vuln_type,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            owasp_category=owasp_category,
            owasp_name=owasp_name,
            affected_url=raw.affected_url,
            affected_parameter=raw.affected_parameter,
            payload_used=raw.payload_used,
            evidence_request=raw.evidence_request,
            evidence_response=raw.evidence_response,
            remediation=remediation,
            confidence=Confidence(raw.confidence),
        )
        self._db.add(finding)
        await self._db.commit()

    async def _update_scan(self, **kwargs) -> None:
        result = await self._db.execute(select(Scan).where(Scan.id == self._scan_id))
        scan = result.scalar_one()
        for key, value in kwargs.items():
            setattr(scan, key, value)
        await self._db.commit()

    async def _mark_failed(self) -> None:
        try:
            await self._update_scan(
                status=ScanStatus.failed,
                completed_at=datetime.now(UTC),
            )
        except Exception:
            logger.exception("Scan %s: could not set status to 'failed'", self._scan_id)

    def _emit(self, phase: str, current: int, total: int) -> None:
        if self._on_progress:
            try:
                self._on_progress(phase, current, total)
            except Exception:
                logger.warning("Scan %s: on_progress callback raised", self._scan_id)

    def _load_modules(self) -> list[BaseModule]:
        enabled: set[str] = set(self._config.get("modules", []))
        modules: list[BaseModule] = []
        for name in enabled:
            spec = _KNOWN_MODULES.get(name)
            if spec is None:
                logger.warning("Scan %s: unknown module %r — skipping", self._scan_id, name)
                continue
            module_path, class_name = spec
            try:
                mod = importlib.import_module(module_path)
                cls: type[BaseModule] = getattr(mod, class_name)
                modules.append(cls())
                logger.debug("Scan %s: loaded module %r", self._scan_id, name)
            except ImportError:
                logger.info("Scan %s: module %r not yet implemented — skipping", self._scan_id, name)
            except Exception:
                logger.exception("Scan %s: failed to load module %r", self._scan_id, name)
        return modules
