import { useMemo, useState } from 'react'

// ── Payload highlighter ─────────────────────────────────────────────────────
// Splits text into alternating { text, match } segments around payload occurrences.
function splitOnPayload(text, payload) {
  if (!payload || !text.includes(payload)) return [{ text, match: false }]
  const parts = []
  let remaining = text
  while (remaining.length > 0) {
    const idx = remaining.indexOf(payload)
    if (idx === -1) { parts.push({ text: remaining, match: false }); break }
    if (idx > 0) parts.push({ text: remaining.slice(0, idx), match: false })
    parts.push({ text: payload, match: true })
    remaining = remaining.slice(idx + payload.length)
  }
  return parts
}

// ── Line-level rendering ────────────────────────────────────────────────────
const METHOD_COLOR = {
  GET: 'text-blue-400', POST: 'text-orange-400', PUT: 'text-yellow-400',
  DELETE: 'text-red-400', PATCH: 'text-purple-400', HEAD: 'text-cyan-400',
  OPTIONS: 'text-gray-400',
}

function statusCodeColor(code) {
  if (code >= 500) return 'text-red-400'
  if (code >= 400) return 'text-orange-400'
  if (code >= 300) return 'text-yellow-400'
  return 'text-green-400'
}

function BodyText({ text, payload }) {
  const segments = useMemo(() => splitOnPayload(text, payload), [text, payload])
  return (
    <>
      {segments.map((seg, i) =>
        seg.match
          ? <mark key={i} className="bg-yellow-300 text-gray-900 rounded-sm px-0.5">{seg.text}</mark>
          : <span key={i} className="text-gray-400">{seg.text}</span>
      )}
    </>
  )
}

// ── Pre-processor: turns raw HTTP text into typed line objects ──────────────
function parseHttpLines(content) {
  const lines = content.split('\n')
  let pastHeaders = false
  return lines.map((text, i) => {
    if (i === 0) {
      return { type: text.startsWith('HTTP/') ? 'status' : 'request', text }
    }
    if (!pastHeaders && text === '') {
      pastHeaders = true
      return { type: 'separator', text }
    }
    if (!pastHeaders && text.includes(': ')) {
      return { type: 'header', text }
    }
    return { type: 'body', text }
  })
}

function HttpContent({ content, payload }) {
  const lines = useMemo(() => parseHttpLines(content), [content])

  return (
    <>
      {lines.map((line, i) => {
        switch (line.type) {
          case 'request': {
            const [method, path, proto, ...rest] = line.text.split(' ')
            const color = METHOD_COLOR[method] ?? 'text-purple-400'
            return (
              <span key={i} className="block">
                <span className={`font-bold ${color}`}>{method}</span>
                {' '}
                <span className="text-gray-200">{path}</span>
                {proto && <span className="text-gray-500"> {proto}{rest.length ? ' ' + rest.join(' ') : ''}</span>}
                {'\n'}
              </span>
            )
          }
          case 'status': {
            const spaceIdx = line.text.indexOf(' ')
            const proto = line.text.slice(0, spaceIdx)
            const rest = line.text.slice(spaceIdx + 1)
            const code = parseInt(rest)
            return (
              <span key={i} className="block">
                <span className="text-gray-500">{proto} </span>
                <span className={`font-bold ${statusCodeColor(code)}`}>{rest}</span>
                {'\n'}
              </span>
            )
          }
          case 'header': {
            const colon = line.text.indexOf(': ')
            const name = line.text.slice(0, colon)
            const value = line.text.slice(colon + 2)
            return (
              <span key={i} className="block">
                <span className="text-indigo-400">{name}</span>
                <span className="text-gray-600">: </span>
                <span className="text-gray-300">{value}</span>
                {'\n'}
              </span>
            )
          }
          case 'separator':
            return <span key={i} className="block">{'\n'}</span>
          default: // body
            return (
              <span key={i} className="block">
                <BodyText text={line.text} payload={payload} />
                {'\n'}
              </span>
            )
        }
      })}
    </>
  )
}

// ── Collapsible evidence block ──────────────────────────────────────────────
function EvidenceBlock({ title, content, payload }) {
  const [open, setOpen] = useState(true)
  const [copied, setCopied] = useState(false)

  if (!content) return null

  function handleCopy() {
    navigator.clipboard?.writeText(content).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 bg-gray-800 border-b border-gray-700">
        <button
          onClick={() => setOpen(v => !v)}
          className="flex items-center gap-2 text-sm font-medium text-gray-200 hover:text-white"
        >
          <span className={`text-xs text-gray-400 transition-transform duration-150 ${open ? '' : '-rotate-90'}`}>▼</span>
          {title}
        </button>
        <button
          onClick={handleCopy}
          className="text-xs text-gray-400 hover:text-gray-200 transition-colors px-2 py-0.5 rounded hover:bg-gray-700"
        >
          {copied ? '✓ Copied' : 'Copy'}
        </button>
      </div>

      {open && (
        <pre className="px-4 py-3 text-xs font-mono bg-gray-950 max-h-80 overflow-y-auto overflow-x-auto leading-relaxed">
          <HttpContent content={content} payload={payload} />
        </pre>
      )}
    </div>
  )
}

// ── Public component ────────────────────────────────────────────────────────
export default function EvidencePanel({ request, response, payload }) {
  return (
    <div className="space-y-3">
      {payload && (
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
            Payload Used
          </p>
          <pre className="bg-gray-950 text-yellow-400 text-xs font-mono px-4 py-3 rounded-lg overflow-x-auto border border-gray-700">
            {payload}
          </pre>
        </div>
      )}
      <EvidenceBlock title="HTTP Request"  content={request}  payload={payload} />
      <EvidenceBlock title="HTTP Response" content={response} payload={payload} />
    </div>
  )
}
