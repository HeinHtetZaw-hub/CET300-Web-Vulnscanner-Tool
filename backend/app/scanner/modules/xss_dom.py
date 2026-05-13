"""DOM-based XSS detection module.

Two detection strategies:
  1. Static analysis — scan the loaded page source for dangerous sink+source patterns
     (e.g. innerHTML assigned from location.hash). Returns a tentative finding.
  2. Dynamic fragment injection — append XSS payloads to the URL fragment (#).
     Fragments are processed client-side only, so this tests whether JS reads
     location.hash and writes it into the DOM. Returns a confirmed finding if an
     alert fires or if a probe element is injected.

This module is OPTIONAL. If Selenium or ChromeDriver is unavailable for any reason,
it logs a warning and returns an empty list instead of raising.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from app.scanner.crawler import FormData, ParameterData
from app.scanner.modules.base import BaseModule, RawFinding
from app.utils.http_client import RateLimitedClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static-analysis patterns — stored as (compiled_regex, human_readable_label)
# ---------------------------------------------------------------------------

_SINK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"document\.write\s*\("),      "document.write()"),
    (re.compile(r"\.innerHTML\s*="),            ".innerHTML ="),
    (re.compile(r"\.outerHTML\s*="),            ".outerHTML ="),
    (re.compile(r"\beval\s*\("),               "eval()"),
    (re.compile(r"\.insertAdjacentHTML\s*\("), ".insertAdjacentHTML()"),
    (re.compile(r"document\.execCommand\s*\("),"document.execCommand()"),
]

_SOURCE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"location\.hash"),    "location.hash"),
    (re.compile(r"location\.search"),  "location.search"),
    (re.compile(r"document\.referrer"),"document.referrer"),
    (re.compile(r"\bwindow\.name\b"),  "window.name"),
    (re.compile(r"location\.href"),    "location.href"),
]

# ---------------------------------------------------------------------------
# Fragment payloads — sent via URL fragment only (never reach the server)
# ---------------------------------------------------------------------------

_FRAGMENT_PAYLOADS: list[str] = [
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<script>alert(1)</script>",
    "<img src=x id=xss-dom-probe>",   # silent probe: just checks DOM injection
]

_WAIT_SECS: float = 0.8   # seconds to wait after navigation for JS to run


def _find_sinks(source: str) -> list[str]:
    """Return human-readable labels for every sink pattern that matches *source*."""
    return [label for pattern, label in _SINK_PATTERNS if pattern.search(source)]


def _find_sources(source: str) -> list[str]:
    """Return human-readable labels for every source pattern that matches *source*."""
    return [label for pattern, label in _SOURCE_PATTERNS if pattern.search(source)]


def _fragment_url(base_url: str, payload: str) -> str:
    """Return *base_url* with any existing fragment replaced by *payload*."""
    return base_url.split("#")[0] + "#" + payload


class DOMXSSModule(BaseModule):
    """Headless-Chrome DOM XSS scanner; skips gracefully if Selenium is absent."""

    @property
    def name(self) -> str:
        return "DOM XSS"

    @property
    def vuln_types(self) -> list[str]:
        return ["xss_dom"]

    async def run(
        self,
        target_urls: set[str],
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        if not target_urls:
            return []

        try:
            findings = await asyncio.to_thread(self._run_sync, list(target_urls))
        except Exception as exc:
            logger.warning("DOM XSS: module aborted unexpectedly — %s", exc)
            findings = []

        return findings

    # ------------------------------------------------------------------
    # Synchronous block — runs in a worker thread via asyncio.to_thread
    # ------------------------------------------------------------------

    def _run_sync(self, urls: list[str]) -> list[RawFinding]:
        try:
            driver = self._create_driver()
        except Exception as exc:
            logger.warning(
                "DOM XSS: Selenium/ChromeDriver unavailable — module skipped. (%s)", exc
            )
            return []

        findings: list[RawFinding] = []
        try:
            for url in urls:
                try:
                    result = self._test_url(url, driver)
                    if result:
                        findings.append(result)
                except Exception:
                    logger.debug("DOM XSS: exception while testing %s — skipping URL", url)
        finally:
            try:
                driver.quit()
            except Exception:
                pass

        return findings

    def _create_driver(self):
        """Create a headless Chrome WebDriver. Raises if Selenium is not installed."""
        from selenium import webdriver  # noqa: PLC0415
        from selenium.webdriver.chrome.options import Options  # noqa: PLC0415

        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1920,1080")
        return webdriver.Chrome(options=opts)

    # ------------------------------------------------------------------
    # Per-URL testing
    # ------------------------------------------------------------------

    def _test_url(self, url: str, driver) -> RawFinding | None:
        # Step 1: load the page and collect the source for static analysis.
        page_source = self._navigate_and_get_source(url, driver)
        if page_source is None:
            return None

        sinks = _find_sinks(page_source)
        sources = _find_sources(page_source)

        # Step 2: inject each payload via URL fragment and test dynamically.
        for payload in _FRAGMENT_PAYLOADS:
            frag_url = _fragment_url(url, payload)
            if not self._navigate(frag_url, driver):
                continue

            if self._check_and_dismiss_alert(driver):
                return RawFinding(
                    vuln_type="xss_dom",
                    affected_url=url,
                    affected_parameter="location.hash",
                    payload_used=payload,
                    evidence_request=f"NAVIGATE {frag_url}",
                    evidence_response="[Alert dialog triggered — payload executed via DOM sink]",
                    confidence="confirmed",
                )

            if self._check_dom_injection(driver):
                return RawFinding(
                    vuln_type="xss_dom",
                    affected_url=url,
                    affected_parameter="location.hash",
                    payload_used=payload,
                    evidence_request=f"NAVIGATE {frag_url}",
                    evidence_response="[DOM element injected — fragment content written into page]",
                    confidence="confirmed",
                )

        # Step 3: fall back to static-analysis tentative finding.
        if sinks and sources:
            return RawFinding(
                vuln_type="xss_dom",
                affected_url=url,
                affected_parameter="DOM sink",
                payload_used="[static analysis — manual verification required]",
                evidence_request=f"NAVIGATE {url}",
                evidence_response=(
                    f"Dangerous sinks: {', '.join(sinks)}\n"
                    f"Tainted sources: {', '.join(sources)}\n"
                    "Sink and source co-occur in page JavaScript; data-flow verification required."
                ),
                confidence="tentative",
            )

        return None

    # ------------------------------------------------------------------
    # Selenium helpers — all wrapped in broad except to handle crashes
    # ------------------------------------------------------------------

    def _navigate_and_get_source(self, url: str, driver) -> str | None:
        try:
            driver.get(url)
            time.sleep(_WAIT_SECS)
            return driver.page_source
        except Exception:
            return None

    def _navigate(self, url: str, driver) -> bool:
        try:
            driver.get(url)
            time.sleep(_WAIT_SECS)
            return True
        except Exception:
            return False

    def _check_and_dismiss_alert(self, driver) -> bool:
        try:
            alert = driver.switch_to.alert
            alert.dismiss()
            return True
        except Exception:
            return False

    def _check_dom_injection(self, driver) -> bool:
        """Return True if a probe img[src=x] element was written into the live DOM."""
        try:
            return bool(
                driver.execute_script(
                    "return document.querySelectorAll('img[src=\"x\"]').length > 0;"
                )
            )
        except Exception:
            return False
