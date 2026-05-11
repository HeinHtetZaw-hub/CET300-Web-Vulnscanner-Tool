"""OWASP Top 10:2025 category mapping and remediation guidance."""

OWASP_MAPPING: dict[str, dict[str, str]] = {
    "sqli_error":         {"category": "A03", "name": "Injection"},
    "sqli_blind_boolean": {"category": "A03", "name": "Injection"},
    "sqli_blind_time":    {"category": "A03", "name": "Injection"},
    "xss_reflected":      {"category": "A03", "name": "Injection"},
    "xss_stored":         {"category": "A03", "name": "Injection"},
    "xss_dom":            {"category": "A03", "name": "Injection"},
    "idor":               {"category": "A01", "name": "Broken Access Control"},
    "ssrf":               {"category": "A01", "name": "Broken Access Control"},
    "misconfig_header":   {"category": "A05", "name": "Security Misconfiguration"},
    "misconfig_file":     {"category": "A05", "name": "Security Misconfiguration"},
    "data_exposure":      {"category": "A02", "name": "Cryptographic Failures"},
}

REMEDIATION: dict[str, str] = {
    "sqli_error": (
        "Use parameterised queries (prepared statements). Never concatenate user input "
        "into SQL strings. Use an ORM. Apply input validation as a secondary defense."
    ),
    "sqli_blind_boolean": (
        "Use parameterised queries (prepared statements). Never concatenate user input "
        "into SQL strings. Use an ORM. Apply input validation as a secondary defense."
    ),
    "sqli_blind_time": (
        "Use parameterised queries (prepared statements). Never concatenate user input "
        "into SQL strings. Use an ORM. Apply input validation as a secondary defense."
    ),
    "xss_reflected": (
        "Encode all user-supplied output using context-appropriate encoding (HTML entity, "
        "JavaScript, URL encoding). Implement Content-Security-Policy header. Use a "
        "templating engine with auto-escaping."
    ),
    "xss_stored": (
        "Encode all user-supplied output using context-appropriate encoding (HTML entity, "
        "JavaScript, URL encoding). Implement Content-Security-Policy header. Use a "
        "templating engine with auto-escaping."
    ),
    "xss_dom": (
        "Encode all user-supplied output using context-appropriate encoding (HTML entity, "
        "JavaScript, URL encoding). Implement Content-Security-Policy header. Use a "
        "templating engine with auto-escaping."
    ),
    "idor": (
        "Implement proper authorisation checks on every request. Use indirect object "
        "references (map user-facing IDs to internal IDs via a server-side mapping). "
        "Validate that the authenticated user has permission to access the requested resource."
    ),
    "ssrf": (
        "Validate and sanitise all user-supplied URLs. Implement an allowlist of permitted "
        "domains and IP ranges. Block requests to private/internal IP ranges. Use a dedicated "
        "HTTP client that cannot reach internal services."
    ),
    "misconfig_header": (
        "Add the missing security headers to your web server configuration. Recommended "
        "headers: Content-Security-Policy, Strict-Transport-Security, "
        "X-Content-Type-Options: nosniff, X-Frame-Options: DENY, "
        "Referrer-Policy: strict-origin-when-cross-origin."
    ),
    "misconfig_file": (
        "Remove or restrict access to sensitive files. Add server rules to deny access to "
        ".env, .git, backup files, and configuration files. Use .htaccess or nginx location "
        "blocks to return 403/404 for these paths."
    ),
    "data_exposure": (
        "Remove exposed credentials and API keys immediately. Rotate all compromised secrets. "
        "Implement proper access controls on sensitive file paths. Use environment variables "
        "for secrets, never commit them to source code."
    ),
}

_UNKNOWN_REMEDIATION = "Review the finding and apply appropriate security controls."


def map_to_owasp(vuln_type: str) -> tuple[str, str]:
    """Return (category_code, category_name) for a vulnerability type.

    Falls back to ('A00', 'Unknown') for unrecognised types.
    """
    entry = OWASP_MAPPING.get(vuln_type)
    if entry is None:
        return "A00", "Unknown"
    return entry["category"], entry["name"]


def get_remediation(vuln_type: str) -> str:
    """Return remediation guidance text for a vulnerability type."""
    return REMEDIATION.get(vuln_type, _UNKNOWN_REMEDIATION)
