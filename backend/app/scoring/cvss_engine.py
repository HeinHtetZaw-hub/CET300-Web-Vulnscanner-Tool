"""CVSS v3.1 score calculation.

Uses the `cvss` Python library when available; falls back to pre-computed values
from scoring/vectors.py so the engine still runs in environments without the library.
"""
from __future__ import annotations

import logging

from app.scoring.vectors import CVSS_SCORES, CVSS_VECTORS

logger = logging.getLogger(__name__)

try:
    from cvss import CVSS3 as _CVSS3
    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS3 = None  # type: ignore[assignment,misc]
    _CVSS_AVAILABLE = False
    logger.warning("cvss library not installed; using pre-computed CVSS scores")


def calculate_cvss(vuln_type: str) -> tuple[float, str, str]:
    """Calculate CVSS v3.1 base score for a vulnerability type.

    Returns:
        (score, severity_label, vector_string)
        severity_label is title-case: 'Critical', 'High', 'Medium', 'Low', 'None'.
        score is 0.0 and severity_label is 'None' for unknown vuln types.
    """
    vector = CVSS_VECTORS.get(vuln_type)
    if vector is None:
        return 0.0, "None", ""

    if _CVSS_AVAILABLE:
        try:
            c = _CVSS3(vector)
            return float(c.base_score), c.severities()[0], vector
        except Exception:
            logger.exception("cvss library failed for vuln_type=%r vector=%r", vuln_type, vector)

    score, severity = CVSS_SCORES.get(vuln_type, (0.0, "None"))
    return score, severity, vector
