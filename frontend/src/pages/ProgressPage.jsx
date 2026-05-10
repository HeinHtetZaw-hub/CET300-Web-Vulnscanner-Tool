import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import client from '../api/client.js'

const STATUS_LABEL = {
  queued:    { text: 'Queued',    color: 'text-gray-500'  },
  crawling:  { text: 'Crawling',  color: 'text-blue-600'  },
  scanning:  { text: 'Scanning',  color: 'text-orange-600'},
  completed: { text: 'Completed', color: 'text-green-600' },
  failed:    { text: 'Failed',    color: 'text-red-600'   },
  cancelled: { text: 'Cancelled', color: 'text-gray-500'  },
}

export default function ProgressPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [error, setError] = useState(null)
  const [cancelling, setCancelling] = useState(false)

  useEffect(() => {
    let timer

    async function poll() {
      try {
        const { data } = await client.get(`/scans/${id}`)
        setScan(data)
        if (data.status === 'completed') {
          navigate(`/scan/${id}/results`)
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
      <div className="max-w-xl mx-auto bg-red-50 border border-red-200 text-red-700 rounded p-6">
        {error}
      </div>
    )
  }

  if (!scan) {
    return <div className="text-center text-gray-400 mt-16">Loading…</div>
  }

  const { text: statusText, color: statusColor } = STATUS_LABEL[scan.status] ?? STATUS_LABEL.queued

  return (
    <div className="max-w-xl mx-auto">
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-8 space-y-6">
        <div>
          <h1 className="text-xl font-bold text-gray-900 mb-1">Scan in Progress</h1>
          <p className="text-sm text-gray-500 break-all">{scan.target_url}</p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-gray-600">Status:</span>
          <span className={`font-semibold ${statusColor}`}>{statusText}</span>
          {['queued', 'crawling', 'scanning'].includes(scan.status) && (
            <svg className="animate-spin h-4 w-4 text-gray-400 ml-1" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
          )}
        </div>

        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="bg-gray-50 rounded p-3 text-center">
            <p className="text-2xl font-bold text-gray-900">{scan.total_urls_found}</p>
            <p className="text-gray-500">URLs found</p>
          </div>
          <div className="bg-gray-50 rounded p-3 text-center">
            <p className="text-2xl font-bold text-red-600">{scan.total_findings}</p>
            <p className="text-gray-500">Findings so far</p>
          </div>
        </div>

        {scan.status === 'failed' && (
          <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded p-3">
            The scan failed. Check the backend logs for details.
          </div>
        )}

        {['queued', 'crawling', 'scanning'].includes(scan.status) && (
          <button
            onClick={handleCancel}
            disabled={cancelling}
            className="w-full border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50 font-medium py-2 rounded transition-colors text-sm"
          >
            {cancelling ? 'Cancelling…' : 'Cancel Scan'}
          </button>
        )}
      </div>
    </div>
  )
}
