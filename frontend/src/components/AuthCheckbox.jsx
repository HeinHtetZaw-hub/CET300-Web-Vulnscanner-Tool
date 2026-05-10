export default function AuthCheckbox({ checked, onChange }) {
  return (
    <label className="flex gap-3 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 h-4 w-4 rounded border-gray-300 text-red-600 focus:ring-red-500 cursor-pointer"
      />
      <span className="text-sm text-gray-700">
        I confirm I have explicit written authorisation to scan this target.
        Unauthorised scanning may violate the{' '}
        <strong>Computer Misuse Act 1990</strong> and the{' '}
        <strong>Myanmar Electronic Transactions Law 2004</strong>.
        I accept full legal responsibility for this scan.
      </span>
    </label>
  )
}
