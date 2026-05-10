import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import client from '../api/client.js'
import AuthCheckbox from '../components/AuthCheckbox.jsx'

export default function ScanPage() {
  const navigate = useNavigate()
  const [url, setUrl] = useState('')
  const [authorised, setAuthorised] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const { data } = await client.post('/scans', {
        target_url: url,
        authorisation_confirmed: true,
      })
      navigate(`/scan/${data.id}/progress`)
    } catch (err) {
      const detail = err.response?.data?.detail
      if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg).join(', '))
      } else {
        setError(detail ?? 'Failed to start scan. Is the backend running?')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-xl mx-auto">
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-8">
        <h1 className="text-2xl font-bold text-gray-900 mb-1">Web Vulnerability Scanner</h1>
        <p className="text-gray-500 text-sm mb-6">
          Automated OWASP Top 10 scanning with CVSS risk scoring.
        </p>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Target URL
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              required
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
            />
          </div>

          <div className="bg-amber-50 border border-amber-200 rounded p-4">
            <AuthCheckbox checked={authorised} onChange={setAuthorised} />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded px-4 py-3">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={!authorised || !url || loading}
            className="w-full bg-red-600 hover:bg-red-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-semibold py-2.5 px-4 rounded transition-colors"
          >
            {loading ? 'Starting scan…' : 'Start Scan'}
          </button>
        </form>
      </div>

      <p className="text-xs text-gray-400 text-center mt-4">
        For authorised security testing only. CET300 Final Year Project — Hein Htet Zaw.
      </p>
    </div>
  )
}
