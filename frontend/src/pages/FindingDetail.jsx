import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import client from '../api/client.js'
import EvidencePanel from '../components/EvidencePanel.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { VULN_TYPE_LABELS } from '../utils/constants.js'

export default function FindingDetail() {
  const { id, fid } = useParams()
  const navigate = useNavigate()
  const [finding, setFinding] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    client.get(`/scans/${id}/findings/${fid}`)
      .then(({ data }) => setFinding(data))
      .catch(() => setError('Finding not found.'))
  }, [id, fid])

  if (error) {
    return <div className="text-red-600 bg-red-50 border border-red-200 rounded p-4">{error}</div>
  }
  if (!finding) {
    return <div className="text-center text-gray-400 mt-16">Loading…</div>
  }

  return (
    <div className="max-w-3xl mx-auto space-y-5">
      <button
        onClick={() => navigate(`/scan/${id}/results`)}
        className="text-sm text-gray-500 hover:text-gray-800 flex items-center gap-1"
      >
        ← Back to results
      </button>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={finding.severity} />
          <span className="font-bold text-gray-900 text-lg">
            {VULN_TYPE_LABELS[finding.vuln_type] ?? finding.vuln_type}
          </span>
          <span className="font-mono text-sm bg-gray-100 text-gray-700 px-2 py-0.5 rounded">
            CVSS {finding.cvss_score.toFixed(1)}
          </span>
          {finding.owasp_category && (
            <span className="bg-indigo-50 text-indigo-700 border border-indigo-200 text-xs font-semibold px-2 py-0.5 rounded">
              {finding.owasp_category} — {finding.owasp_name}
            </span>
          )}
        </div>

        <div className="text-sm text-gray-600 space-y-1">
          <p><span className="font-medium text-gray-800">URL:</span> <span className="font-mono break-all">{finding.affected_url}</span></p>
          {finding.affected_parameter && (
            <p><span className="font-medium text-gray-800">Parameter:</span> <span className="font-mono">{finding.affected_parameter}</span></p>
          )}
          <p><span className="font-medium text-gray-800">Confidence:</span> {finding.confidence}</p>
          {finding.cvss_vector && (
            <p><span className="font-medium text-gray-800">CVSS Vector:</span> <span className="font-mono text-xs">{finding.cvss_vector}</span></p>
          )}
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 space-y-3">
        <h2 className="font-semibold text-gray-800">Evidence</h2>
        <EvidencePanel
          payload={finding.payload_used}
          request={finding.evidence_request}
          response={finding.evidence_response}
        />
      </div>

      {finding.remediation && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="font-semibold text-gray-800 mb-2">Remediation</h2>
          <p className="text-sm text-gray-700 leading-relaxed">{finding.remediation}</p>
        </div>
      )}
    </div>
  )
}
