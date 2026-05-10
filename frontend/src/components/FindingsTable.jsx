import { useNavigate } from 'react-router-dom'
import { VULN_TYPE_LABELS } from '../utils/constants.js'
import SeverityBadge from './SeverityBadge.jsx'

const COLUMNS = [
  { key: 'severity',     label: 'Severity',      sortable: true  },
  { key: 'vuln_type',    label: 'Vulnerability',  sortable: false },
  { key: 'affected_url', label: 'Affected URL',   sortable: false },
  { key: 'affected_parameter', label: 'Parameter', sortable: false },
  { key: 'cvss_score',   label: 'CVSS',           sortable: true  },
  { key: 'owasp_category', label: 'OWASP',        sortable: false },
]

export default function FindingsTable({ findings, scanId, sortBy, order, onSort }) {
  const navigate = useNavigate()

  function handleSort(col) {
    if (!col.sortable) return
    const newOrder = sortBy === col.key && order === 'desc' ? 'asc' : 'desc'
    onSort(col.key, newOrder)
  }

  return (
    <div className="overflow-x-auto rounded border border-gray-200">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="bg-gray-50">
          <tr>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                onClick={() => handleSort(col)}
                className={`px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide ${col.sortable ? 'cursor-pointer hover:text-gray-800 select-none' : ''}`}
              >
                {col.label}
                {col.sortable && sortBy === col.key && (
                  <span className="ml-1">{order === 'desc' ? '↓' : '↑'}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 bg-white">
          {findings.length === 0 && (
            <tr>
              <td colSpan={COLUMNS.length} className="px-4 py-8 text-center text-gray-400">
                No findings match your filters.
              </td>
            </tr>
          )}
          {findings.map((f) => (
            <tr
              key={f.id}
              onClick={() => navigate(`/scan/${scanId}/findings/${f.id}`)}
              className="hover:bg-gray-50 cursor-pointer"
            >
              <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
              <td className="px-4 py-3 font-medium text-gray-800">
                {VULN_TYPE_LABELS[f.vuln_type] ?? f.vuln_type}
              </td>
              <td className="px-4 py-3 text-gray-600 max-w-xs truncate" title={f.affected_url}>
                {f.affected_url}
              </td>
              <td className="px-4 py-3 text-gray-500 font-mono text-xs">{f.affected_parameter ?? '—'}</td>
              <td className="px-4 py-3 font-semibold text-gray-800">{f.cvss_score.toFixed(1)}</td>
              <td className="px-4 py-3">
                {f.owasp_category && (
                  <span className="inline-block bg-indigo-50 text-indigo-700 border border-indigo-200 rounded px-2 py-0.5 text-xs font-semibold">
                    {f.owasp_category}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
