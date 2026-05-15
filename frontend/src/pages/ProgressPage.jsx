import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import client from '../api/client.js'

const STATUS_META = {
  queued:    { label: 'Queued',    color: 'text-gray-500',   active: false },
  crawling:  { label: 'Crawling',  color: 'text-blue-600',   active: true  },
  scanning:  { label: 'Scanning',  color: 'text-orange-600', active: true  },
  completed: { label: 'Completed', color: 'text-green-600',  active: false },
  failed:    { label: 'Failed',    color: 'text-red-600',    active: false },
  cancelled: { label: 'Cancelled', color: 'text-gray-500',   active: false },
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_STYLE = {
  critical: 'bg-red-600 text-white',
  high:     'bg-orange-500 text-white',
  medium:   'bg-yellow-400 text-gray-900',
  low:      'bg-blue-500 text-white',
  info:     'bg-gray-400 text-white',
}

const MODULE_CONFIG_MAP = {
  sqli:          'SQL Injection',
  xss_reflected: 'Reflected XSS',
  xss_stored:    'Stored XSS',
  xss_dom:       'DOM XSS',
  bac:           'Broken Access Control',
  misconfig:     'Security Misconfiguration',
  exposure:      'Sensitive Data Exposure',
}

function Spinner() {
  return (
    <svg className="animate-spin h-4 w-4 text-gray-400 inline ml-1" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
    </svg>
  )
}

function PulseBar() {
  return (
    <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
      <div className="h-3 rounded-full bg-blue-500 animate-pulse" style={{ width: '100%' }} />
    </div>
  )
}

function ProgressBar({ pct, color = 'bg-orange-500' }) {
  return (
    <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
      <div
        className={`${color} h-3 rounded-full transition-all duration-500`}
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}

export default function ProgressPage() {
  const { id } = useParams()
  const navigate = useNavigate()

  const [scan, setScan] = useState(null)
  const [error, setError] = useState(null)
  const [cancelling, setCancelling] = useState(false)
  const [logs, setLogs] = useState([])
  const [completedModules, setCompletedModules] = useState([])

  const prevStatus = useRef(null)
  const prevModule = useRef(null)
  const logEndRef = useRef(null)

  function addLog(message) {
    const time = new Date().toLocaleTimeString()
    setLogs(prev => [...prev, { time, message, id: Date.now() + Math.random() }])
  }

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  useEffect(() => {
    let timer

    async function poll() {
      try {
        const { data } = await client.get(`/scans/${id}/progress`)
        setScan(data)

        if (data.status !== prevStatus.current) {
          if (!prevStatus.current) {
            addLog('Scan started')
          }
          if (data.status === 'crawling') {
            addLog('Crawling web pages — discovering URLs and forms')
          } else if (data.status === 'scanning') {
            addLog(`Found ${data.total_urls_found} URL(s) — starting vulnerability scan`)
          } else if (data.status === 'completed') {
            addLog(`Scan complete — ${data.total_findings} finding(s) recorded`)
          } else if (data.status === 'failed') {
            addLog('Scan failed — check backend logs for details')
          } else if (data.status === 'cancelled') {
            addLog('Scan cancelled by user')
          }
          prevStatus.current = data.status
        }

        if (data.current_module && data.current_module !== prevModule.current) {
          if (prevModule.current) {
            setCompletedModules(prev =>
              prev.includes(prevModule.current) ? prev : [...prev, prevModule.current]
            )
          }
          addLog(`Running module: ${data.current_module}`)
          prevModule.current = data.current_module
        }

        if (!data.current_module && prevModule.current) {
          setCompletedModules(prev =>
            prev.includes(prevModule.current) ? prev : [...prev, prevModule.current]
          )
          prevModule.current = null
        }

        if (data.status === 'completed') {
          setTimeout(() => navigate(`/scan/${id}/results`), 1500)
          return
        }

        if (data.status !== 'failed' && data.status !== 'cancelled') {
          timer = setTimeout(poll, 2000)
        }
      } catch {
        setError('Could not reach the backend. Is the server running?')
      }
    }

    poll()
    return () => clearTimeout(timer)
  }, [id, navigate])

  async function handleCancel() {
    setCancelling(true)
    try {
      await client.post(`/scans/${id}/cancel`)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail ?? 'Cancel failed.')
      setCancelling(false)
    }
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto bg-red-50 border border-red-200 text-red-700 rounded-lg p-6 text-sm">
        {error}
      </div>
    )
  }

  if (!scan) {
    return <div className="text-center text-gray-400 mt-16 text-sm">Loading…</div>
  }

  const { label: statusLabel, color: statusColor, active: isActive } =
    STATUS_META[scan.status] ?? STATUS_META.queued

  const enabledModules = (scan.config?.modules ?? []).map(k => MODULE_CONFIG_MAP[k] ?? k)
  const totalModules = enabledModules.length
  const doneCount = completedModules.length
  const modulePct = totalModules > 0 ? Math.round((doneCount / totalModules) * 100) : 0

  const findingsBySev = scan.findings_by_severity ?? {}
  const hasSevData = SEV_ORDER.some(s => findingsBySev[s] > 0)

  return (
    <div className="max-w-2xl mx-auto space-y-4">

      {/* Header card */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6">
        <div className="flex items-start justify-between">
          <div className="min-w-0">
            <h1 className="text-lg font-bold text-gray-900">Scan in Progress</h1>
            <p className="text-sm text-gray-500 break-all mt-0.5">{scan.target_url}</p>
          </div>
          <div className="flex items-center gap-1.5 shrink-0 ml-4">
            <span className={`font-semibold text-sm ${statusColor}`}>{statusLabel}</span>
            {isActive && <Spinner />}
          </div>
        </div>
      </div>

      {/* Phase progress card */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">Phase Progress</h2>

        {/* Crawling phase */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-sm">
            <span className="font-medium text-gray-700">
              {scan.status === 'crawling' ? 'Crawling pages' : 'Crawl complete'}
            </span>
            <span className="text-gray-500">{scan.total_urls_found} URL{scan.total_urls_found !== 1 ? 's' : ''} found</span>
          </div>
          {scan.status === 'crawling'
            ? <PulseBar />
            : <ProgressBar pct={scan.total_urls_found > 0 ? 100 : 0} color="bg-green-500" />
          }
        </div>

        {/* Scanning phase */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-sm">
            <span className="font-medium text-gray-700">
              {scan.status === 'scanning'
                ? `Running: ${scan.current_module ?? '…'}`
                : scan.status === 'completed'
                  ? 'Scan complete'
                  : 'Vulnerability scan'}
            </span>
            {totalModules > 0 && (
              <span className="text-gray-500">
                {scan.status === 'completed' ? totalModules : doneCount} / {totalModules} modules
              </span>
            )}
          </div>
          {scan.status === 'scanning'
            ? <ProgressBar pct={modulePct} color="bg-orange-500" />
            : scan.status === 'completed'
              ? <ProgressBar pct={100} color="bg-green-500" />
              : <ProgressBar pct={0} color="bg-orange-500" />
          }
        </div>

        {/* Module list (only during/after scanning) */}
        {['scanning', 'completed'].includes(scan.status) && enabledModules.length > 0 && (
          <div className="grid grid-cols-2 gap-1 pt-1">
            {enabledModules.map(name => {
              const done = completedModules.includes(name)
              const running = scan.current_module === name
              return (
                <div
                  key={name}
                  className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded ${
                    done
                      ? 'text-green-700 bg-green-50'
                      : running
                        ? 'text-orange-700 bg-orange-50 font-medium'
                        : 'text-gray-400 bg-gray-50'
                  }`}
                >
                  <span>{done ? '✓' : running ? '▶' : '○'}</span>
                  <span>{name}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Findings summary card */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">Findings So Far</h2>
          <span className="text-2xl font-bold text-gray-900">{scan.total_findings}</span>
        </div>

        {hasSevData ? (
          <div className="flex flex-wrap gap-2">
            {SEV_ORDER.filter(s => findingsBySev[s] > 0).map(s => (
              <span
                key={s}
                className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold ${SEV_STYLE[s]}`}
              >
                {s.charAt(0).toUpperCase() + s.slice(1)}: {findingsBySev[s]}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-400">
            {isActive ? 'No findings yet — scanning in progress' : 'No findings recorded'}
          </p>
        )}
      </div>

      {/* Activity log card */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-6">
        <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-3">Activity Log</h2>
        <div className="h-40 overflow-y-auto bg-gray-950 rounded-md p-3 font-mono text-xs space-y-0.5">
          {logs.length === 0 ? (
            <span className="text-gray-500">Waiting for scan to start…</span>
          ) : (
            logs.map(entry => (
              <div key={entry.id} className="flex gap-2">
                <span className="text-gray-500 shrink-0">{entry.time}</span>
                <span className="text-green-400">{entry.message}</span>
              </div>
            ))
          )}
          <div ref={logEndRef} />
        </div>
      </div>

      {/* Failed error */}
      {scan.status === 'failed' && (
        <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-4">
          The scan encountered an unrecoverable error. Check backend logs for details.
        </div>
      )}

      {/* Cancel button */}
      {isActive && (
        <button
          onClick={handleCancel}
          disabled={cancelling}
          className="w-full border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50 font-medium py-2.5 rounded-lg transition-colors text-sm"
        >
          {cancelling ? 'Cancelling…' : 'Cancel Scan'}
        </button>
      )}

      {/* Redirect notice */}
      {scan.status === 'completed' && (
        <p className="text-center text-sm text-green-600 font-medium">
          Redirecting to results…
        </p>
      )}
    </div>
  )
}
