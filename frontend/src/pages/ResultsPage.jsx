import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import client from '../api/client.js'
import FindingsTable from '../components/FindingsTable.jsx'
import OWASPFilter from '../components/OWASPFilter.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export default function ResultsPage() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [total, setTotal] = useState(0)
  const [severity, setSeverity] = useState('')
  const [owasp, setOwasp] = useState('')
  const [sortBy, setSortBy] = useState('cvss_score')
  const [order, setOrder] = useState('desc')
  const [error, setError] = useState(null)

  useEffect(() => {
    client.get(`/scans/${id}`).then(({ data }) => setScan(data)).catch(() => {})
  }, [id])

  useEffect(() => {
    const params = new URLSearchParams({ sort_by: sortBy, order, limit: 200 })
    if (severity) params.set('severity', severity)
    if (owasp) params.set('owasp_category', owasp)

    client.get(`/scans/${id}/findings?${params}`)
      .then(({ data }) => { setFindings(data.items); setTotal(data.total) })
      .catch(() => setError('Failed to load findings.'))
  }, [id, severity, owasp, sortBy, order])

  function handleSort(col, dir) {
    setSortBy(col)
    setOrder(dir)
  }

  if (error) {
    return <div className="text-red-600 bg-red-50 border border-red-200 rounded p-4">{error}</div>
  }

  const counts = SEVERITIES.reduce((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h1 className="text-xl font-bold text-gray-900 mb-1">Scan Results</h1>
        {scan && <p className="text-sm text-gray-500 break-all">{scan.target_url}</p>}
      </div>

      <div className="grid grid-cols-5 gap-3">
        {SEVERITIES.map((s) => (
          <button
            key={s}
            onClick={() => setSeverity(severity === s ? '' : s)}
            className={`bg-white border rounded-lg p-3 text-center transition-all ${severity === s ? 'ring-2 ring-offset-1 ring-red-500' : 'hover:shadow-sm'}`}
          >
            <p className="text-2xl font-bold text-gray-900">{counts[s]}</p>
            <SeverityBadge severity={s} />
          </button>
        ))}
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <span className="text-sm text-gray-600 font-medium">
            {findings.length} of {total} findings
          </span>
          <OWASPFilter value={owasp} onChange={setOwasp} />
          {(severity || owasp) && (
            <button
              onClick={() => { setSeverity(''); setOwasp('') }}
              className="text-xs text-gray-500 hover:text-gray-800 underline"
            >
              Clear filters
            </button>
          )}
          <div className="ml-auto flex gap-2">
            <a
              href={`/api/v1/scans/${id}/report/pdf`}
              className="text-sm bg-gray-900 text-white px-3 py-1.5 rounded hover:bg-gray-700 transition-colors"
            >
              Download PDF
            </a>
            <a
              href={`/api/v1/scans/${id}/report/json`}
              className="text-sm border border-gray-300 text-gray-700 px-3 py-1.5 rounded hover:bg-gray-50 transition-colors"
            >
              Export JSON
            </a>
          </div>
        </div>

        <FindingsTable
          findings={findings}
          scanId={id}
          sortBy={sortBy}
          order={order}
          onSort={handleSort}
        />
      </div>
    </div>
  )
}
