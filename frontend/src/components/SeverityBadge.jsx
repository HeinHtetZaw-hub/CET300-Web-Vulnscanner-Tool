import { SEVERITY_STYLES } from '../utils/constants.js'

export default function SeverityBadge({ severity }) {
  const styles = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide border ${styles.bg} ${styles.text} ${styles.border}`}>
      {severity}
    </span>
  )
}
