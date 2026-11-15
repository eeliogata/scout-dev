const fixturePrefixes = [
  '[DEMO] ',
  'PREWRITTEN SYNTHETIC DEMO ALERT, not a Modal finding. ',
  'Demo exercise: ',
]

export function alertDisplayText(text: string): string {
  const prefix = fixturePrefixes.find(value => text.startsWith(value))
  return prefix ? text.slice(prefix.length) : text
}

export function companyDisplayName(name: string): string {
  return name.replace(/^Demo\s+/, '')
}
