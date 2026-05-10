export const SEVERITY_STYLES = {
  critical: { bg: 'bg-red-100',    text: 'text-red-700',    border: 'border-red-300'    },
  high:     { bg: 'bg-orange-100', text: 'text-orange-700', border: 'border-orange-300' },
  medium:   { bg: 'bg-yellow-100', text: 'text-yellow-700', border: 'border-yellow-300' },
  low:      { bg: 'bg-blue-100',   text: 'text-blue-700',   border: 'border-blue-300'   },
  info:     { bg: 'bg-gray-100',   text: 'text-gray-600',   border: 'border-gray-300'   },
}

export const OWASP_CATEGORIES = [
  { code: 'A01', name: 'Broken Access Control' },
  { code: 'A02', name: 'Cryptographic Failures' },
  { code: 'A03', name: 'Injection' },
  { code: 'A04', name: 'Insecure Design' },
  { code: 'A05', name: 'Security Misconfiguration' },
  { code: 'A06', name: 'Vulnerable Components' },
  { code: 'A07', name: 'Auth Failures' },
  { code: 'A08', name: 'Software Integrity Failures' },
  { code: 'A09', name: 'Logging Failures' },
  { code: 'A10', name: 'SSRF' },
]

export const VULN_TYPE_LABELS = {
  sqli_error:         'SQL Injection (Error-based)',
  sqli_blind_boolean: 'SQL Injection (Boolean Blind)',
  sqli_blind_time:    'SQL Injection (Time Blind)',
  xss_reflected:      'XSS (Reflected)',
  xss_stored:         'XSS (Stored)',
  xss_dom:            'XSS (DOM-based)',
  idor:               'Broken Access Control (IDOR)',
  ssrf:               'SSRF',
  misconfig_header:   'Missing Security Header',
  misconfig_file:     'Exposed Sensitive File',
  data_exposure:      'Sensitive Data Exposure',
}
