"""CVSS v3.1 vector strings and pre-computed scores for every vulnerability type.

Pre-computed scores are used as a fallback when the cvss library is unavailable.
"""

CVSS_VECTORS: dict[str, str] = {
    # SQL Injection — network, low complexity, no privs, no interaction, changed scope, high CIA
    "sqli_error":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "sqli_blind_boolean":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "sqli_blind_time":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",

    # XSS Reflected — needs user interaction
    "xss_reflected":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    # XSS Stored — no user interaction needed for trigger
    "xss_stored":          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
    # XSS DOM-based
    "xss_dom":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",

    # IDOR — access control bypass
    "idor":                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    # SSRF
    "ssrf":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",

    # Security Misconfiguration — missing headers
    "misconfig_header":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    # Exposed sensitive files
    "misconfig_file":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",

    # Sensitive data exposure
    "data_exposure":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# Pre-computed (score, severity) pairs — used when cvss library is unavailable
CVSS_SCORES: dict[str, tuple[float, str]] = {
    "sqli_error":          (10.0, "Critical"),
    "sqli_blind_boolean":  (10.0, "Critical"),
    "sqli_blind_time":     (10.0, "Critical"),
    "xss_reflected":       (6.1,  "Medium"),
    "xss_stored":          (6.4,  "Medium"),
    "xss_dom":             (6.1,  "Medium"),
    "idor":                (8.1,  "High"),
    "ssrf":                (8.6,  "High"),
    "misconfig_header":    (5.3,  "Medium"),
    "misconfig_file":      (7.5,  "High"),
    "data_exposure":       (7.5,  "High"),
}
