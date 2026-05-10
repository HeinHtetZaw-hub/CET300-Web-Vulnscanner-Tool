import { OWASP_CATEGORIES } from '../utils/constants.js'

export default function OWASPFilter({ value, onChange }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500"
    >
      <option value="">All OWASP Categories</option>
      {OWASP_CATEGORIES.map(({ code, name }) => (
        <option key={code} value={code}>{code} — {name}</option>
      ))}
    </select>
  )
}
