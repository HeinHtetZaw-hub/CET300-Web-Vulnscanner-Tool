import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import client from '../api/client.js'
import EvidencePanel from '../components/EvidencePanel.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { SEVERITY_STYLES, VULN_TYPE_LABELS } from '../utils/constants.js'

// OWASP Top 10 documentation links (2021 edition — published reference)
const OWASP_LINKS = {
  A01: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  A02: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  A03: 'https://owasp.org/Top10/A03_2021-Injection/',
  A04: 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  A05: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  A06: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  A07: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  A08: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  A09: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
  A10: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
}

// Split remediation text into bullet sentences for readable display
function parseRemediation(text) {
  if (!text) return []
  return text
    .split(/(?<=\.)\s+/)
    .map(s => s.trim())
    .filter(Boolean)
}

function MetaRow({ label, children }) {
  return (
    <div className="flex gap-2 text-sm min-w-0">
      <span className="font-medium text-gray-600 shrink-0 w-28">{label}</span>
      <span className="text-gray-800 min-w-0 break-all font-mono text-xs leading-relaxed">
        {children}
      </span>
    </div>
  )
}

export default function FindingDetail() {
  const { id, fid } = useParams()
  const navigate = useNavigate()
  const [finding, setFinding] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    client.get(`/scans/${id}/findings/${fid}`)
      .then(({ data }) => setFinding(data))
      .catch(() => setError('Finding not found or failed to load.'))
  }, [id, fid])

  if (error) {
    return (
      <div className="max-w-3xl mx-auto bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 text-sm">
        {error}
      </div>
    )
  }

  if (!finding) {
    return <div className="text-center text-gray-400 mt-16 text-sm">Loading…</div>
  }

  const vulnLabel = VULN_TYPE_LABELS[finding.vuln_type] ?? finding.vuln_type
  const sevStyle = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info
  const owaspLink = finding.owasp_category ? OWASP_LINKS[finding.owasp_category] : null
  const remediationLines = parseRemediation(finding.remediation)

  return (
    <div className="max-w-3xl mx-auto space-y-5">

      {/* Back navigation */}
      <button
        onClick={() => navigate(`/scan/${id}/results`)}
        className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 transition-colors"
      >
        <span>←</span> Back to results
      </button>

      {/* ── Section 1: Header ────────────────────────────────────────── */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6">
        <div className="flex flex-wrap items-center gap-2.5 mb-4">
          <SeverityBadge severity={finding.severity} />

          {/* CVSS score badge */}
          <span className={`font-mono text-sm font-bold px-2.5 py-0.5 rounded border ${sevStyle.bg} ${sevStyle.text} ${sevStyle.border}`}>
            CVSS {finding.cvss_score.toFixed(1)}
          </span>

          {/* OWASP category badge */}
          {finding.owasp_category && (
            <span className="bg-indigo-50 text-indigo-700 border border-indigo-200 text-xs font-semibold px-2.5 py-0.5 rounded">
              {finding.owasp_category}
              {finding.owasp_name ? ` — ${finding.owasp_name}` : ''}
            </span>
          )}

          {/* Confidence badge */}
          <span className={`text-xs font-semibold px-2.5 py-0.5 rounded border ${
            finding.confidence === 'confirmed'
              ? 'bg-green-50 text-green-700 border-green-200'
              : 'bg-yellow-50 text-yellow-700 border-yellow-200'
          }`}>
            {finding.confidence === 'confirmed' ? '✓ Confirmed' : '~ Tentative'}
          </span>
        </div>

        <h1 className="text-xl font-bold text-gray-900">{vulnLabel}</h1>
      </div>

      {/* ── Section 2: Affected target + metadata ────────────────────── */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6 space-y-3">
        <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">Target</h2>

        <div className="space-y-2.5">
          <div className="flex gap-2 text-sm min-w-0">
            <span className="font-medium text-gray-600 shrink-0 w-28">Affected URL</span>
            <span className="text-gray-800 min-w-0 break-all text-xs font-mono leading-relaxed">
              {finding.affected_url}
            </span>
          </div>

          {finding.affected_parameter && (
            <MetaRow label="Parameter">{finding.affected_parameter}</MetaRow>
          )}

          {finding.cvss_vector && (
            <MetaRow label="CVSS Vector">{finding.cvss_vector}</MetaRow>
          )}
        </div>
      </div>

      {/* ── Section 3: Evidence ──────────────────────────────────────── */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6">
        <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-4">
          Evidence
        </h2>
        <EvidencePanel
          payload={finding.payload_used}
          request={finding.evidence_request}
          response={finding.evidence_response}
        />
      </div>

      {/* ── Section 4: Remediation ───────────────────────────────────── */}
      {(finding.remediation || owaspLink) && (
        <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6">
          <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-3">
            Remediation
          </h2>

          {remediationLines.length > 0 && (
            <ul className="space-y-1.5 mb-4">
              {remediationLines.map((line, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-700 leading-relaxed">
                  <span className="text-gray-400 shrink-0 mt-0.5">•</span>
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          )}

          {owaspLink && (
            <a
              href={owaspLink}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-sm text-indigo-600 hover:text-indigo-800 font-medium transition-colors"
            >
              OWASP {finding.owasp_category} — {finding.owasp_name} documentation
              <span className="text-xs">↗</span>
            </a>
          )}
        </div>
      )}

    </div>
  )
}
