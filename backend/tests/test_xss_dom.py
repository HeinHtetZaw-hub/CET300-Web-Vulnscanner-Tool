"""Tests for the DOM-based XSS detection module.

All Selenium interactions are replaced with MagicMock drivers so the test suite
runs without a browser. The module's _create_driver() method is patched on each
module instance, and time.sleep() is suppressed throughout.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.scanner.modules.xss_dom import (
    DOMXSSModule,
    _find_sinks,
    _find_sources,
    _fragment_url,
)
from app.utils.http_client import RateLimitedClient


# ---------------------------------------------------------------------------
# Mock driver factory
# ---------------------------------------------------------------------------


def _make_driver(
    page_source: str = "<html><body></body></html>",
    alert_text: str | None = None,
    dom_injected: bool = False,
    get_raises: bool = False,
) -> MagicMock:
    """Return a MagicMock that mimics a Selenium WebDriver.

    Args:
        page_source:   Returned by ``driver.page_source``.
        alert_text:    If set, ``driver.switch_to.alert`` returns a dismissible alert.
                       If None, accessing it raises Exception (no alert present).
        dom_injected:  Return value of ``driver.execute_script(…)``.
        get_raises:    If True, ``driver.get()`` raises Exception on every call.
    """
    driver = MagicMock()

    if get_raises:
        driver.get.side_effect = Exception("WebDriver error")
    else:
        driver.get.return_value = None

    type(driver).page_source = property(lambda self: page_source)  # type: ignore[assignment]

    if alert_text is not None:
        alert_mock = MagicMock()
        alert_mock.text = alert_text
        driver.switch_to.alert = alert_mock
    else:
        type(driver.switch_to).alert = property(  # type: ignore[assignment]
            lambda self: (_ for _ in ()).throw(Exception("no alert"))
        )

    driver.execute_script.return_value = dom_injected
    return driver


def _make_http_client() -> MagicMock:
    return MagicMock(spec=RateLimitedClient)


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_driver_fails_returns_empty():
    """If _create_driver raises (e.g. no chromedriver), module returns []."""
    module = DOMXSSModule()
    with patch.object(module, "_create_driver", side_effect=Exception("no chromedriver")):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())
    assert findings == []


@pytest.mark.asyncio
async def test_empty_target_urls_returns_empty():
    module = DOMXSSModule()
    findings = await module.run(set(), [], [], _make_http_client())
    assert findings == []


@pytest.mark.asyncio
async def test_import_error_returns_empty():
    """ImportError from missing selenium package → empty list, no crash."""
    module = DOMXSSModule()
    with patch.object(module, "_create_driver", side_effect=ImportError("No module named 'selenium'")):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())
    assert findings == []


# ---------------------------------------------------------------------------
# Alert-based confirmed detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_triggered_confirmed_finding():
    """Alert dialog fired after fragment injection → confirmed xss_dom."""
    module = DOMXSSModule()
    driver = _make_driver(alert_text="1")

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/page"}, [], [], _make_http_client())

    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "xss_dom"
    assert f.confidence == "confirmed"
    assert f.affected_url == "http://example.com/page"
    assert f.affected_parameter == "location.hash"
    assert "Alert dialog triggered" in f.evidence_response
    assert "NAVIGATE" in f.evidence_request
    assert "#" in f.evidence_request


@pytest.mark.asyncio
async def test_alert_finding_records_payload_used():
    module = DOMXSSModule()
    driver = _make_driver(alert_text="1")

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    # payload_used should be one of the _FRAGMENT_PAYLOADS (containing onerror or onload)
    assert findings[0].payload_used in (
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<script>alert(1)</script>",
        "<img src=x id=xss-dom-probe>",
    )


# ---------------------------------------------------------------------------
# DOM injection confirmed detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dom_injection_confirmed_finding():
    """img[src=x] found in DOM after fragment injection → confirmed (no alert needed)."""
    module = DOMXSSModule()
    driver = _make_driver(dom_injected=True)   # no alert, but DOM was modified

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "xss_dom"
    assert f.confidence == "confirmed"
    assert "DOM element injected" in f.evidence_response


# ---------------------------------------------------------------------------
# Static analysis tentative detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_static_sink_and_source_tentative_finding():
    """Page JS has both a dangerous sink and a tainted source → tentative."""
    source = (
        "<script>"
        "var data = location.hash.slice(1);"
        "document.getElementById('out').innerHTML = data;"
        "</script>"
    )
    module = DOMXSSModule()
    driver = _make_driver(page_source=source)  # no alert, no DOM injection

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "xss_dom"
    assert f.confidence == "tentative"
    assert "location.hash" in f.evidence_response    # human-readable source label
    assert ".innerHTML =" in f.evidence_response       # human-readable sink label
    assert "manual verification" in f.payload_used


@pytest.mark.asyncio
async def test_sink_without_source_no_static_finding():
    """Dangerous sink but no tainted source → not flagged."""
    source = "<script>el.innerHTML = 'hardcoded value';</script>"
    module = DOMXSSModule()
    driver = _make_driver(page_source=source)

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    assert findings == []


@pytest.mark.asyncio
async def test_source_without_sink_no_static_finding():
    """Tainted source but no dangerous sink → not flagged."""
    source = "<script>var h = location.hash; console.log(h);</script>"
    module = DOMXSSModule()
    driver = _make_driver(page_source=source)

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    assert findings == []


@pytest.mark.asyncio
async def test_clean_page_no_finding():
    module = DOMXSSModule()
    driver = _make_driver()

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    assert findings == []


# ---------------------------------------------------------------------------
# Priority: dynamic confirmed > static tentative
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dynamic_confirmed_returned_even_when_static_also_matches():
    """Alert fires AND page has sink+source — confirmed must be returned, not tentative."""
    source = "<script>el.innerHTML = location.hash;</script>"
    module = DOMXSSModule()
    driver = _make_driver(page_source=source, alert_text="1")

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"


# ---------------------------------------------------------------------------
# Multiple URLs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multiple_urls_each_tested():
    """Each URL in target_urls is tested independently."""
    urls = {"http://example.com/a", "http://example.com/b"}
    tested: list[str] = []

    def mock_test_url(url, driver):
        tested.append(url)
        return None

    module = DOMXSSModule()
    driver = _make_driver()
    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
        patch.object(module, "_test_url", side_effect=mock_test_url),
    ):
        await module.run(urls, [], [], _make_http_client())

    assert len(tested) == 2
    assert set(tested) == urls


@pytest.mark.asyncio
async def test_multiple_urls_can_return_multiple_findings():
    source = "<script>el.innerHTML = location.hash;</script>"
    module = DOMXSSModule()
    # Alert fires for every URL
    driver = _make_driver(page_source=source, alert_text="1")

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run(
            {"http://example.com/a", "http://example.com/b"}, [], [], _make_http_client()
        )

    assert len(findings) == 2
    assert all(f.confidence == "confirmed" for f in findings)


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exception_on_one_url_continues_to_others():
    """RuntimeError testing one URL must not abort the rest."""
    urls = {"http://example.com/crash", "http://example.com/ok"}
    tested: list[str] = []

    def mock_test_url(url, driver):
        tested.append(url)
        if "crash" in url:
            raise RuntimeError("WebDriver crashed")
        return None

    module = DOMXSSModule()
    driver = _make_driver()
    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
        patch.object(module, "_test_url", side_effect=mock_test_url),
    ):
        findings = await module.run(urls, [], [], _make_http_client())

    assert len(tested) == 2  # both URLs were attempted
    assert findings == []


@pytest.mark.asyncio
async def test_driver_quit_called_on_clean_run():
    module = DOMXSSModule()
    driver = _make_driver()

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        await module.run({"http://example.com/"}, [], [], _make_http_client())

    driver.quit.assert_called_once()


@pytest.mark.asyncio
async def test_driver_quit_called_even_after_url_exception():
    """driver.quit() must be called even when a URL test raises."""
    module = DOMXSSModule()
    driver = _make_driver()

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
        patch.object(module, "_test_url", side_effect=RuntimeError("boom")),
    ):
        await module.run({"http://example.com/"}, [], [], _make_http_client())

    driver.quit.assert_called_once()


@pytest.mark.asyncio
async def test_navigate_failure_returns_none_for_url():
    """If driver.get() always raises, _test_url returns None (no finding, no crash)."""
    module = DOMXSSModule()
    driver = _make_driver(get_raises=True)

    with (
        patch.object(module, "_create_driver", return_value=driver),
        patch("app.scanner.modules.xss_dom.time.sleep"),
    ):
        findings = await module.run({"http://example.com/"}, [], [], _make_http_client())

    assert findings == []


# ---------------------------------------------------------------------------
# _find_sinks unit tests
# ---------------------------------------------------------------------------


def test_find_sinks_innerHTML():
    assert any("innerHTML" in s for s in _find_sinks("el.innerHTML = data;"))

def test_find_sinks_outerHTML():
    assert any("outerHTML" in s for s in _find_sinks("el.outerHTML = x;"))

def test_find_sinks_document_write():
    assert any("document.write" in s for s in _find_sinks("document.write(x);"))

def test_find_sinks_eval():
    assert any("eval" in s for s in _find_sinks("eval(userInput);"))

def test_find_sinks_insertAdjacentHTML():
    assert any("insertAdjacentHTML" in s for s in _find_sinks("el.insertAdjacentHTML('beforeend', x);"))

def test_find_sinks_empty_for_safe_js():
    assert _find_sinks("var x = 1; console.log(x);") == []


# ---------------------------------------------------------------------------
# _find_sources unit tests
# ---------------------------------------------------------------------------


def test_find_sources_location_hash():
    assert any("location.hash" in s for s in _find_sources("var h = location.hash;"))

def test_find_sources_location_search():
    assert any("location.search" in s for s in _find_sources("qs = location.search;"))

def test_find_sources_document_referrer():
    assert any("document.referrer" in s for s in _find_sources("ref = document.referrer;"))

def test_find_sources_window_name():
    assert any("window.name" in s for s in _find_sources("var n = window.name;"))

def test_find_sources_location_href():
    assert any("location.href" in s for s in _find_sources("window.location.href;"))

def test_find_sources_empty_for_safe_js():
    assert _find_sources("var x = 1;") == []


# ---------------------------------------------------------------------------
# _fragment_url unit tests
# ---------------------------------------------------------------------------


def test_fragment_url_appends_payload():
    result = _fragment_url("http://example.com/page", "<img>")
    assert result == "http://example.com/page#<img>"


def test_fragment_url_strips_existing_fragment():
    result = _fragment_url("http://example.com/page#old", "<svg>")
    assert result == "http://example.com/page#<svg>"


def test_fragment_url_works_with_query_string():
    result = _fragment_url("http://example.com/?q=1", "payload")
    assert result == "http://example.com/?q=1#payload"


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------


def test_module_metadata():
    m = DOMXSSModule()
    assert m.name == "DOM XSS"
    assert m.vuln_types == ["xss_dom"]
