import { useNavigate } from 'react-router-dom'
import { VULN_TYPE_LABELS } from '../utils/constants.js'
import SeverityBadge from './SeverityBadge.jsx'

const COLUMNS = [
  { key: 'severity',           label: 'Severity',     sortable: true  },
  { key: 'vuln_type',          label: 'Vulnerability', sortable: false },
  { key: 'affected_url',       label: 'Affected URL',  sortable: false },
  { key: 'affected_parameter', label: 'Parameter',     sortable: false },
  { key: 'cvss_score',         label: 'CVSS',          sortable: true  },
  { key: 'owasp_category',     label: 'OWASP',         sortable: false },
]

export default function FindingsTable({ findings, scanId, totalFindings, sortBy, order, onSort }) {
  const navigate = useNavigate()

  function handleHeaderClick(col) {
    if (!col.sortable) return
    const newOrder = sortBy === col.key && order === 'desc' ? 'asc' : 'desc'
    onSort(col.key, newOrder)
  }

  const noFindings = findings.length === 0

  return (
    <div className="overflow-x-auto rounded border border-gray-200">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="bg-gray-50">
          <tr>
            {COLUMNS.map(col => (
              <th
                key={col.key}
                onClick={() => handleHeaderClick(col)}
                className={`px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap ${
                  col.sortable ? 'cursor-pointer select-none hover:text-gray-800' : ''
                }`}
              >
                {col.label}
                {col.sortable && sortBy === col.key && (
                  <span className="ml-1 text-gray-700">{order === 'desc' ? '↓' : '↑'}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>

        <tbody className="divide-y divide-gray-100 bg-white">
          {noFindings ? (
            <tr>
              <td colSpan={COLUMNS.length} className="px-4 py-14 text-center text-gray-400 text-sm">
                {totalFindings === 0
                  ? 'No vulnerabilities were detected during this scan.'
                  : 'No findings match the current filters.'}
              </td>
            </tr>
          ) : (
            findings.map(f => (
              <tr
                key={f.id}
                onClick={() => navigate(`/scan/${scanId}/findings/${f.id}`)}
                className="hover:bg-gray-50 cursor-pointer transition-colors"
              >
                {/* Severity */}
                <td className="px-4 py-3 whitespace-nowrap">
                  <SeverityBadge severity={f.severity} />
                </td>

                {/* Vuln type + confidence */}
                <td className="px-4 py-3">
                  <span className="font-medium text-gray-800 block">
                    {VULN_TYPE_LABELS[f.vuln_type] ?? f.vuln_type}
                  </span>
                  {f.confidence === 'tentative' && (
                    <span className="text-xs text-gray-400">tentative</span>
                  )}
                </td>

                {/* Affected URL */}
                <td className="px-4 py-3 max-w-xs">
                  <span
                    className="block truncate text-gray-600 text-xs font-mono"
                    title={f.affected_url}
                  >
                    {f.affected_url}
                  </span>
                </td>

                {/* Parameter */}
                <td className="px-4 py-3 whitespace-nowrap text-gray-500 font-mono text-xs">
                  {f.affected_parameter ?? <span className="text-gray-300">—</span>}
                </td>

                {/* CVSS score */}
                <td className="px-4 py-3 whitespace-nowrap">
                  <span className="font-bold text-gray-900">{f.cvss_score.toFixed(1)}</span>
                </td>

                {/* OWASP category + name */}
                <td className="px-4 py-3 whitespace-nowrap">
                  {f.owasp_category ? (
                    <>
                      <span className="inline-block bg-indigo-50 text-indigo-700 border border-indigo-200 rounded px-2 py-0.5 text-xs font-semibold">
                        {f.owasp_category}
                      </span>
                      {f.owasp_name && (
                        <span className="block text-xs text-gray-400 mt-0.5">{f.owasp_name}</span>
                      )}
                    </>
                  ) : (
                    <span className="text-gray-300">—</span>
                  )}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}
