import { Facts } from './components'
import type { PostVersion, Range } from './types'

function range(value: Range) {
  if (value.minimum === value.maximum && value.minimum !== null) return String(value.minimum)
  return `${value.minimum ?? 'Unknown'}–${value.maximum ?? 'Unknown'}`
}

export function TargetGroups({ version, matched = [] }: { version: PostVersion; matched?: string[] }) {
  if (version.classification.target_extraction_status !== 'complete') {
    return <p className="muted">Target extraction needs review. See the original post for the source claims.</p>
  }
  if (!version.targets?.length) return <p className="muted">No separate target claims were recorded for this post.</p>
  return <div className="target-groups">{version.targets.map(({ id, label, facts }) => {
    const { employees, revenue } = facts
    return <article key={id} className="target-group">
      <h3>{label}</h3>
      {matched.includes(id) && <p className="muted">Matched in this alert</p>}
      <Facts heading="h4" title="Company names and domains" items={[...facts.company_names, ...facts.domains]} />
      <Facts heading="h4" title="Industry and countries" items={[...(facts.industry ? [facts.industry] : []), ...facts.countries]} />
      <Facts heading="h4" title="Company size" items={[
        employees ? `Employees: ${range(employees)}` : 'Employees: Unknown',
        revenue ? `Revenue: ${range(revenue)} ${revenue.currency ?? '(currency unknown)'} · ${revenue.period ?? 'Period unknown'}` : 'Revenue: Unknown',
      ]} />
      <Facts heading="h4" title="Technologies" items={facts.technologies} />
      {!!facts.evidence.length && <details><summary>Supporting quotes</summary>{facts.evidence.map(({ field, quote }, index) =>
        <blockquote key={index}>{quote}<footer className="muted">{field.replaceAll('_', ' ')}</footer></blockquote>,
      )}</details>}
    </article>
  })}</div>
}
