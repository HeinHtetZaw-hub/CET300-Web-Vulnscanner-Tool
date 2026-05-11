"""Tests for the BaseModule abstract class and RawFinding dataclass."""
from __future__ import annotations

import pytest

from app.scanner.crawler import ParameterData
from app.scanner.modules.base import BaseModule, RawFinding

# ---------------------------------------------------------------------------
# Minimal concrete subclass used throughout the tests
# ---------------------------------------------------------------------------

class _EchoModule(BaseModule):
    """Returns a single hard-coded finding — used to verify interface."""

    @property
    def name(self) -> str:
        return "Echo"

    @property
    def vuln_types(self) -> list[str]:
        return ["sqli_error"]

    async def run(
        self,
        target_urls,
        forms,
        parameters,
        http_client,
    ) -> list[RawFinding]:
        return [
            RawFinding(
                vuln_type="sqli_error",
                affected_url="http://example.com/page",
                affected_parameter="id",
                payload_used="' OR 1=1--",
                evidence_request="GET /page?id='+OR+1%3D1-- HTTP/1.1",
                evidence_response="You have an error in your SQL syntax",
                confidence="confirmed",
            )
        ]


class _EmptyModule(BaseModule):
    """Returns no findings — verifies the empty-list path."""

    @property
    def name(self) -> str:
        return "Empty"

    @property
    def vuln_types(self) -> list[str]:
        return ["xss_reflected"]

    async def run(self, target_urls, forms, parameters, http_client) -> list[RawFinding]:
        return []


# ---------------------------------------------------------------------------
# RawFinding tests
# ---------------------------------------------------------------------------

def test_raw_finding_fields():
    f = RawFinding(
        vuln_type="xss_reflected",
        affected_url="http://example.com",
        affected_parameter="q",
        payload_used="<script>alert(1)</script>",
        evidence_request="GET /?q=<script> HTTP/1.1",
        evidence_response="<script>alert(1)</script>",
        confidence="tentative",
    )
    assert f.vuln_type == "xss_reflected"
    assert f.affected_url == "http://example.com"
    assert f.affected_parameter == "q"
    assert f.confidence == "tentative"


def test_raw_finding_confirmed():
    f = RawFinding(
        vuln_type="sqli_error",
        affected_url="http://example.com/login",
        affected_parameter="username",
        payload_used="'",
        evidence_request="POST /login HTTP/1.1",
        evidence_response="SQL syntax error",
        confidence="confirmed",
    )
    assert f.confidence == "confirmed"


# ---------------------------------------------------------------------------
# BaseModule interface tests
# ---------------------------------------------------------------------------

def test_base_module_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseModule()  # type: ignore[abstract]


def test_concrete_module_name():
    m = _EchoModule()
    assert m.name == "Echo"


def test_concrete_module_vuln_types():
    m = _EchoModule()
    assert m.vuln_types == ["sqli_error"]


@pytest.mark.asyncio
async def test_run_returns_raw_findings():
    m = _EchoModule()
    results = await m.run(
        target_urls={"http://example.com/page"},
        forms=[],
        parameters=[ParameterData(url="http://example.com/page", param_name="id", param_location="query")],
        http_client=None,  # not used by the echo module
    )
    assert len(results) == 1
    finding = results[0]
    assert isinstance(finding, RawFinding)
    assert finding.vuln_type == "sqli_error"
    assert finding.confidence == "confirmed"


@pytest.mark.asyncio
async def test_run_can_return_empty_list():
    m = _EmptyModule()
    results = await m.run(
        target_urls=set(),
        forms=[],
        parameters=[],
        http_client=None,
    )
    assert results == []


def test_multiple_vuln_types():
    class _MultiModule(BaseModule):
        @property
        def name(self):
            return "Multi"

        @property
        def vuln_types(self):
            return ["sqli_error", "sqli_blind_boolean", "sqli_blind_time"]

        async def run(self, target_urls, forms, parameters, http_client):
            return []

    m = _MultiModule()
    assert len(m.vuln_types) == 3
    assert "sqli_blind_time" in m.vuln_types


def test_subclass_missing_run_raises():
    """A class that only implements name + vuln_types but not run() is still abstract."""
    class _Partial(BaseModule):
        @property
        def name(self):
            return "Partial"

        @property
        def vuln_types(self):
            return []

    with pytest.raises(TypeError):
        _Partial()  # type: ignore[abstract]
