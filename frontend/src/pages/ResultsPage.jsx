import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import client from '../api/client.js'
import FindingsTable from '../components/FindingsTable.jsx'
import OWASPFilter from '../components/OWASPFilter.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { SEVERITY_STYLES } from '../utils/constants.js'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

function formatDuration(startedAt, completedAt) {
  if (!startedAt || !completedAt) return null
  const secs = Math.round((new Date(completedAt) - new Date(startedAt)) / 1000)
  if (secs < 60) return `${secs}s`
  return `${Math.floor(secs / 60)}m ${secs % 60}s`
}

export default function ResultsPage() {
  const { id } = useParams()

  const [scan, setScan] = useState(null)
  const [sevCounts, setSevCounts] = useState({})
  const [findings, setFindings] = useState([])
  const [totalFiltered, setTotalFiltered] = useState(0)
  const [loadingFindings, setLoadingFindings] = useState(true)

  const [severity, setSeverity] = useState('')
  const [owasp, setOwasp] = useState('')
  const [sortBy, setSortBy] = useState('cvss_score')
  const [order, setOrder] = useState('desc')
  const [error, setError] = useState(null)

  // Fetch scan metadata + accurate per-severity counts once
  useEffect(() => {
    client.get(`/scans/${id}`).then(({ data }) => setScan(data)).catch(() => {})
    client.get(`/scans/${id}/progress`)
      .then(({ data }) => setSevCounts(data.findings_by_severity ?? {}))
      .catch(() => {})
  }, [id])

  // Re-fetch findings whenever filters or sort changes
  useEffect(() => {
    setLoadingFindings(true)
    const params = new URLSearchParams({ sort_by: sortBy, order, limit: 200 })
    if (severity) params.set('severity', severity)
    if (owasp) params.set('owasp_category', owasp)

    client.get(`/scans/${id}/findings?${params}`)
      .then(({ data }) => {
        setFindings(data.items)
        setTotalFiltered(data.total)
      })
      .catch(() => setError('Failed to load findings. Is the backend running?'))
      .finally(() => setLoadingFindings(false))
  }, [id, severity, owasp, sortBy, order])

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 text-sm">
        {error}
      </div>
    )
  }

  const totalFindings = scan?.total_findings ?? 0
  const isFiltered = Boolean(severity || owasp)
  const duration = formatDuration(scan?.started_at, scan?.completed_at)

  function toggleSeverity(s) {
    setSeverity(prev => (prev === s ? '' : s))
  }

  function clearFilters() {
    setSeverity('')
    setOwasp('')
  }

  return (
    <div className="space-y-5">

      {/* Scan header */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-xl font-bold text-gray-900">Scan Results</h1>
            {scan && (
              <p className="text-sm text-gray-500 break-all mt-0.5">{scan.target_url}</p>
            )}
          </div>
          <span className="shrink-0 text-xs font-semibold uppercase tracking-wide px-2 py-1 rounded bg-green-100 text-green-700 border border-green-200">
            Completed
          </span>
        </div>

        {scan && (
          <div className="flex flex-wrap gap-x-6 gap-y-1 mt-3 text-xs text-gray-500">
            {scan.completed_at && (
              <span>Completed: {new Date(scan.completed_at).toLocaleString()}</span>
            )}
            {duration && <span>Duration: {duration}</span>}
            <span>URLs crawled: {scan.total_urls_found}</span>
            <span>Total findings: {totalFindings}</span>
          </div>
        )}
      </div>

      {/* Severity summary — clickable to filter */}
      <div className="grid grid-cols-5 gap-3">
        {SEVERITIES.map(s => {
          const count = sevCounts[s] ?? 0
          const active = severity === s
          const style = SEVERITY_STYLES[s]
          return (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              disabled={count === 0}
              className={`bg-white border rounded-lg p-3 text-center transition-all ${
                active
                  ? `ring-2 ring-offset-1 ${style.border} shadow-sm`
                  : count > 0
                    ? 'hover:shadow-sm border-gray-200 hover:border-gray-300'
                    : 'border-gray-100 opacity-40 cursor-default'
              }`}
            >
              <p className={`text-2xl font-bold ${active ? style.text : 'text-gray-900'}`}>
                {count}
              </p>
              <SeverityBadge severity={s} />
            </button>
          )
        })}
      </div>

      {/* Findings table card */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-4">

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <span className="text-sm text-gray-600 font-medium">
            {isFiltered
              ? `${totalFiltered} of ${totalFindings} finding${totalFindings !== 1 ? 's' : ''}`
              : `${totalFindings} finding${totalFindings !== 1 ? 's' : ''}`}
          </span>

          <OWASPFilter value={owasp} onChange={setOwasp} />

          {isFiltered && (
            <button
              onClick={clearFilters}
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

        {loadingFindings ? (
          <div className="py-16 text-center text-sm text-gray-400">Loading findings…</div>
        ) : (
          <FindingsTable
            findings={findings}
            scanId={id}
            totalFindings={totalFindings}
            sortBy={sortBy}
            order={order}
            onSort={(col, dir) => { setSortBy(col); setOrder(dir) }}
          />
        )}
      </div>
    </div>
  )
}
