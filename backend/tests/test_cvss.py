"""Unit tests for the CVSS v3.1 scoring engine.

Tests verify that calculate_cvss() returns the correct score, severity label,
and vector string for every known vulnerability type, and that the pre-computed
fallback values match the live cvss library (when installed).
"""
from __future__ import annotations

import pytest

from app.scoring.cvss_engine import calculate_cvss
from app.scoring.vectors import CVSS_SCORES, CVSS_VECTORS


# ---------------------------------------------------------------------------
# Parametrised: all 11 vulnerability types against pre-computed ground truth
# ---------------------------------------------------------------------------

_EXPECTED: list[tuple[str, float, str]] = [
    ("sqli_error",         10.0, "Critical"),
    ("sqli_blind_boolean", 10.0, "Critical"),
    ("sqli_blind_time",    10.0, "Critical"),
    ("xss_reflected",       6.1, "Medium"),
    ("xss_stored",          6.4, "Medium"),
    ("xss_dom",             6.1, "Medium"),
    ("idor",                8.1, "High"),
    ("ssrf",                8.6, "High"),
    ("misconfig_header",    5.3, "Medium"),
    ("misconfig_file",      7.5, "High"),
    ("data_exposure",       7.5, "High"),
]


@pytest.mark.parametrize("vuln_type,expected_score,expected_severity", _EXPECTED)
def test_score_matches_expected(vuln_type: str, expected_score: float, expected_severity: str):
    score, severity, vector = calculate_cvss(vuln_type)
    assert score == expected_score, f"{vuln_type}: got {score}, expected {expected_score}"
    assert severity == expected_severity, f"{vuln_type}: got {severity!r}, expected {expected_severity!r}"


@pytest.mark.parametrize("vuln_type,expected_score,expected_severity", _EXPECTED)
def test_vector_string_returned(vuln_type: str, expected_score: float, expected_severity: str):
    _, _, vector = calculate_cvss(vuln_type)
    assert vector == CVSS_VECTORS[vuln_type]
    assert vector.startswith("CVSS:3.1/")


# ---------------------------------------------------------------------------
# Score range validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vuln_type", list(CVSS_VECTORS.keys()))
def test_score_within_valid_cvss_range(vuln_type: str):
    score, _, _ = calculate_cvss(vuln_type)
    assert 0.0 <= score <= 10.0


# ---------------------------------------------------------------------------
# Severity label consistency
# ---------------------------------------------------------------------------

_SEVERITY_RANGES = [
    ("sqli_error",     "Critical", 9.0),
    ("sqli_blind_boolean", "Critical", 9.0),
    ("sqli_blind_time",    "Critical", 9.0),
    ("ssrf",           "High",     7.0),
    ("idor",           "High",     7.0),
    ("misconfig_file", "High",     7.0),
    ("data_exposure",  "High",     7.0),
    ("xss_stored",     "Medium",   4.0),
    ("xss_reflected",  "Medium",   4.0),
    ("xss_dom",        "Medium",   4.0),
    ("misconfig_header","Medium",  4.0),
]


@pytest.mark.parametrize("vuln_type,expected_severity,min_score", _SEVERITY_RANGES)
def test_severity_consistent_with_score(vuln_type: str, expected_severity: str, min_score: float):
    score, severity, _ = calculate_cvss(vuln_type)
    assert severity == expected_severity
    assert score >= min_score


# ---------------------------------------------------------------------------
# Unknown vuln_type fallback
# ---------------------------------------------------------------------------


def test_unknown_vuln_type_returns_zero_score():
    score, severity, vector = calculate_cvss("completely_unknown")
    assert score == 0.0


def test_unknown_vuln_type_returns_none_severity():
    _, severity, _ = calculate_cvss("completely_unknown")
    assert severity == "None"


def test_unknown_vuln_type_returns_empty_vector():
    _, _, vector = calculate_cvss("completely_unknown")
    assert vector == ""


# ---------------------------------------------------------------------------
# Pre-computed fallback values match live library
# ---------------------------------------------------------------------------

try:
    from cvss import CVSS3 as _CVSS3
    _LIBRARY_AVAILABLE = True
except ImportError:
    _LIBRARY_AVAILABLE = False


@pytest.mark.skipif(not _LIBRARY_AVAILABLE, reason="cvss library not installed")
@pytest.mark.parametrize("vuln_type", list(CVSS_VECTORS.keys()))
def test_precomputed_matches_library(vuln_type: str):
    """Pre-computed (score, severity) must exactly match the live cvss library output."""
    vector = CVSS_VECTORS[vuln_type]
    c = _CVSS3(vector)
    library_score = float(c.base_score)
    library_severity = c.severities()[0]

    pre_score, pre_severity = CVSS_SCORES[vuln_type]
    assert pre_score == library_score, (
        f"{vuln_type}: pre-computed {pre_score} != library {library_score}"
    )
    assert pre_severity == library_severity, (
        f"{vuln_type}: pre-computed {pre_severity!r} != library {library_severity!r}"
    )


@pytest.mark.skipif(not _LIBRARY_AVAILABLE, reason="cvss library not installed")
@pytest.mark.parametrize("vuln_type,expected_score,expected_severity", _EXPECTED)
def test_calculate_cvss_uses_library_when_available(
    vuln_type: str, expected_score: float, expected_severity: str
):
    """With the library installed, calculate_cvss() must return library-derived values."""
    score, severity, vector = calculate_cvss(vuln_type)
    assert score == expected_score
    assert severity == expected_severity
    assert vector.startswith("CVSS:3.1/")


# ---------------------------------------------------------------------------
# Return-type guarantees
# ---------------------------------------------------------------------------


def test_return_is_three_tuple():
    result = calculate_cvss("sqli_error")
    assert isinstance(result, tuple)
    assert len(result) == 3


def test_score_is_float():
    score, _, _ = calculate_cvss("sqli_error")
    assert isinstance(score, float)


def test_severity_is_string():
    _, severity, _ = calculate_cvss("xss_reflected")
    assert isinstance(severity, str)


def test_vector_is_string():
    _, _, vector = calculate_cvss("idor")
    assert isinstance(vector, str)


# ---------------------------------------------------------------------------
# SQL injection types produce the highest scores
# ---------------------------------------------------------------------------


def test_sqli_scores_are_maximum():
    for vuln_type in ("sqli_error", "sqli_blind_boolean", "sqli_blind_time"):
        score, _, _ = calculate_cvss(vuln_type)
        assert score == 10.0, f"{vuln_type} should be 10.0"


# ---------------------------------------------------------------------------
# XSS score ordering: stored > reflected == dom
# ---------------------------------------------------------------------------


def test_xss_stored_higher_than_reflected():
    stored_score, _, _ = calculate_cvss("xss_stored")
    reflected_score, _, _ = calculate_cvss("xss_reflected")
    assert stored_score > reflected_score


def test_xss_reflected_equals_dom():
    reflected_score, _, _ = calculate_cvss("xss_reflected")
    dom_score, _, _ = calculate_cvss("xss_dom")
    assert reflected_score == dom_score
