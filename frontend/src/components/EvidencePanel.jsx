import { useState } from 'react'

function Block({ title, content }) {
  const [open, setOpen] = useState(false)
  if (!content) return null
  return (
    <div className="border border-gray-200 rounded">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2 text-sm font-medium text-gray-700 bg-gray-50 hover:bg-gray-100 transition-colors"
      >
        {title}
        <span>{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <pre className="px-4 py-3 text-xs font-mono text-gray-800 whitespace-pre-wrap overflow-x-auto bg-white max-h-64 overflow-y-auto">
          {content}
        </pre>
      )}
    </div>
  )
}

export default function EvidencePanel({ request, response, payload }) {
  return (
    <div className="space-y-2">
      {payload && (
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Payload Used</p>
          <pre className="bg-gray-900 text-green-400 text-xs font-mono px-4 py-2 rounded overflow-x-auto">{payload}</pre>
        </div>
      )}
      <Block title="HTTP Request" content={request} />
      <Block title="HTTP Response" content={response} />
    </div>
  )
}
