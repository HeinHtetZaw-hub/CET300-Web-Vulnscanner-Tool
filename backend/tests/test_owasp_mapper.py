"""Unit tests for the OWASP Top 10:2025 mapper and remediation guide.

Verifies:
  - Every known vulnerability type maps to the correct OWASP category and name.
  - Unknown types fall back gracefully.
  - Remediation text exists and contains the key advice prescribed in the project plan.
"""
from __future__ import annotations

import pytest

from app.mapping.owasp_mapper import (
    OWASP_MAPPING,
    REMEDIATION,
    get_remediation,
    map_to_owasp,
)


# ---------------------------------------------------------------------------
# Parametrised OWASP category mapping
# ---------------------------------------------------------------------------

_EXPECTED_MAPPING: list[tuple[str, str, str]] = [
    # SQL Injection → A03 Injection
    ("sqli_error",         "A03", "Injection"),
    ("sqli_blind_boolean", "A03", "Injection"),
    ("sqli_blind_time",    "A03", "Injection"),
    # XSS → A03 Injection
    ("xss_reflected",      "A03", "Injection"),
    ("xss_stored",         "A03", "Injection"),
    ("xss_dom",            "A03", "Injection"),
    # Access control → A01 Broken Access Control
    ("idor",               "A01", "Broken Access Control"),
    ("ssrf",               "A01", "Broken Access Control"),
    # Security misconfiguration → A05
    ("misconfig_header",   "A05", "Security Misconfiguration"),
    ("misconfig_file",     "A05", "Security Misconfiguration"),
    # Sensitive data → A02 Cryptographic Failures
    ("data_exposure",      "A02", "Cryptographic Failures"),
]


@pytest.mark.parametrize("vuln_type,expected_cat,expected_name", _EXPECTED_MAPPING)
def test_map_to_owasp_category(vuln_type: str, expected_cat: str, expected_name: str):
    cat, name = map_to_owasp(vuln_type)
    assert cat == expected_cat
    assert name == expected_name


# ---------------------------------------------------------------------------
# Unknown type fallback
# ---------------------------------------------------------------------------


def test_unknown_type_returns_a00():
    cat, name = map_to_owasp("not_a_real_vuln_type")
    assert cat == "A00"


def test_unknown_type_name_is_unknown():
    _, name = map_to_owasp("not_a_real_vuln_type")
    assert name == "Unknown"


# ---------------------------------------------------------------------------
# Return-type guarantees
# ---------------------------------------------------------------------------


def test_map_to_owasp_returns_two_tuple():
    result = map_to_owasp("sqli_error")
    assert isinstance(result, tuple)
    assert len(result) == 2


def test_both_values_are_strings():
    cat, name = map_to_owasp("xss_reflected")
    assert isinstance(cat, str)
    assert isinstance(name, str)


def test_category_code_format():
    """All category codes should be A01–A10 (or A00 for unknown)."""
    for vuln_type in OWASP_MAPPING:
        cat, _ = map_to_owasp(vuln_type)
        assert cat.startswith("A")
        assert cat[1:].isdigit()


# ---------------------------------------------------------------------------
# Injection group completeness
# ---------------------------------------------------------------------------


def test_all_sqli_types_are_injection():
    for vt in ("sqli_error", "sqli_blind_boolean", "sqli_blind_time"):
        cat, name = map_to_owasp(vt)
        assert cat == "A03"
        assert name == "Injection"


def test_all_xss_types_are_injection():
    for vt in ("xss_reflected", "xss_stored", "xss_dom"):
        cat, name = map_to_owasp(vt)
        assert cat == "A03"
        assert name == "Injection"


def test_all_access_control_types():
    for vt in ("idor", "ssrf"):
        cat, name = map_to_owasp(vt)
        assert cat == "A01"
        assert name == "Broken Access Control"


# ---------------------------------------------------------------------------
# Remediation content — parametrised key-phrase checks
# ---------------------------------------------------------------------------

_REMEDIATION_KEYWORDS: list[tuple[str, str]] = [
    # SQL injection: must mention parameterised queries
    ("sqli_error",         "parameterised"),
    ("sqli_blind_boolean", "parameterised"),
    ("sqli_blind_time",    "parameterised"),
    # XSS: must mention Content-Security-Policy
    ("xss_reflected",      "Content-Security-Policy"),
    ("xss_stored",         "Content-Security-Policy"),
    ("xss_dom",            "Content-Security-Policy"),
    # IDOR: must mention authorisation checks
    ("idor",               "authorisation"),
    # SSRF: must mention allowlist
    ("ssrf",               "allowlist"),
    # Missing headers: must mention security headers
    ("misconfig_header",   "security headers"),
    # Exposed files: must mention sensitive files
    ("misconfig_file",     "sensitive files"),
    # Data exposure: must mention credentials
    ("data_exposure",      "credentials"),
]


@pytest.mark.parametrize("vuln_type,keyword", _REMEDIATION_KEYWORDS)
def test_remediation_contains_key_advice(vuln_type: str, keyword: str):
    text = get_remediation(vuln_type)
    assert keyword in text, (
        f"Remediation for {vuln_type!r} should contain {keyword!r}; got: {text!r}"
    )


@pytest.mark.parametrize("vuln_type,keyword", _REMEDIATION_KEYWORDS)
def test_remediation_is_non_empty(vuln_type: str, keyword: str):
    text = get_remediation(vuln_type)
    assert len(text) > 50, f"Remediation for {vuln_type!r} is too short: {text!r}"


# ---------------------------------------------------------------------------
# Remediation for unknown type
# ---------------------------------------------------------------------------


def test_unknown_type_remediation_is_not_empty():
    text = get_remediation("completely_unknown_vuln")
    assert isinstance(text, str)
    assert len(text) > 0


def test_unknown_type_remediation_differs_from_known():
    known = get_remediation("sqli_error")
    unknown = get_remediation("completely_unknown_vuln")
    assert known != unknown


# ---------------------------------------------------------------------------
# Coverage: every type in OWASP_MAPPING has a remediation entry
# ---------------------------------------------------------------------------


def test_all_mapped_types_have_remediation():
    for vuln_type in OWASP_MAPPING:
        text = get_remediation(vuln_type)
        assert text != "Review the finding and apply appropriate security controls.", (
            f"{vuln_type!r} should have specific remediation, not the generic fallback"
        )


def test_all_mapped_types_have_non_empty_remediation():
    for vuln_type in OWASP_MAPPING:
        assert len(get_remediation(vuln_type)) > 50


# ---------------------------------------------------------------------------
# REMEDIATION dict coverage
# ---------------------------------------------------------------------------


def test_remediation_dict_covers_all_owasp_keys():
    """Every key in OWASP_MAPPING should have a dedicated entry in REMEDIATION."""
    missing = set(OWASP_MAPPING.keys()) - set(REMEDIATION.keys())
    assert missing == set(), f"Missing remediation for: {missing}"


def test_no_extra_remediation_keys():
    """REMEDIATION should not contain keys absent from OWASP_MAPPING (orphans)."""
    orphans = set(REMEDIATION.keys()) - set(OWASP_MAPPING.keys())
    assert orphans == set(), f"Orphaned remediation entries: {orphans}"
