import { useState } from 'react'
import type { FormEvent } from 'react'
import { api, errorMessage } from './api'
import { companyDisplayName } from './alertDisplay'
import { Button, ErrorNotice, Field } from './components'
import type { Company, CompanyProfile } from './types'

const split = (value: string) => value.split(/\r?\n/).map(item => item.trim()).filter(Boolean)
const number = (value: string) => value.trim() ? Number(value) : null

export function ProfileForm({ company, onSaved, notice = '', onDismissNotice }: {
  company?: Company
  notice?: string
  onDismissNotice?: () => void
  onSaved: (company: Company) => void
}) {
  const [initialValues] = useState<Record<string, string>>({
    name: companyDisplayName(company?.name || ''), industry: company?.industry || '',
    aliases: company?.aliases.join('\n') || '', domains: company?.domains.join('\n') || '',
    countries: company?.countries.join('\n') || '', technologies: company?.technologies.join('\n') || '',
    employeeMin: String(company?.employees?.minimum ?? ''), employeeMax: String(company?.employees?.maximum ?? ''),
    revenueMin: String(company?.revenue?.minimum ?? ''), revenueMax: String(company?.revenue?.maximum ?? ''),
    currency: company?.revenue?.currency || '', period: company?.revenue?.period || '',
  })
  const [values, setValues] = useState(initialValues)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [localNotice, setLocalNotice] = useState('')
  const [validation, setValidation] = useState<Record<string, string>>({})
  function update(name: string, value: string) {
    setValues(current => ({ ...current, [name]: value }))
    setValidation(current => ({ ...current, [name]: '' }))
    setLocalNotice('')
    onDismissNotice?.()
  }
  function field(name: string, label: string, hint?: string, numeric = false) {
    return <Field label={label} hint={hint}>{id => <>
      <input id={id} name={name} value={values[name]} required={name === 'name'} type={numeric ? 'number' : 'text'} min={numeric ? 0 : undefined} step={numeric ? (name.startsWith('employee') ? '1' : 'any') : undefined}
        aria-invalid={!!validation[name]} aria-describedby={[hint ? `${id}-hint` : '', validation[name] ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined}
        onChange={event => update(name, event.target.value)} />
      {validation[name] && <small id={`${id}-error`} className="field-error">{validation[name]}</small>}
    </>}</Field>
  }
  function listField(name: string, label: string) {
    return <Field label={label} hint="One entry per line. Commas stay within an entry.">{id =>
      <textarea id={id} name={name} aria-describedby={`${id}-hint`} rows={name === 'technologies' ? 6 : 2} value={values[name]} onChange={event => update(name, event.target.value)} />
    }</Field>
  }
  async function save(event: FormEvent) {
    event.preventDefault()
    setError('')
    setLocalNotice('')
    onDismissNotice?.()
    const invalid: Record<string, string> = {}
    if (!values.name.trim()) invalid.name = 'Enter a company name.'
    for (const [minimum, maximum] of [['employeeMin', 'employeeMax'], ['revenueMin', 'revenueMax']]) {
      if (values[minimum] && values[maximum] && Number(values[minimum]) > Number(values[maximum])) invalid[maximum] = 'Maximum must be at least the minimum.'
    }
    setValidation(invalid)
    if (Object.keys(invalid).length) return
    const employees = { minimum: number(values.employeeMin), maximum: number(values.employeeMax) }
    const revenue = {
      minimum: number(values.revenueMin), maximum: number(values.revenueMax),
      currency: company && values.currency === initialValues.currency ? company.revenue?.currency ?? null : values.currency.trim() || null,
      period: company && values.period === initialValues.period ? company.revenue?.period ?? null : values.period.trim() || null,
    }
    const profile: CompanyProfile = {
      name: values.name.trim(), industry: values.industry.trim() || null,
      aliases: split(values.aliases), domains: split(values.domains), countries: split(values.countries), technologies: split(values.technologies),
      employees: Object.values(employees).some(value => value !== null) ? employees : null,
      revenue: Object.values(revenue).some(value => value !== null) ? revenue : null,
    }
    const payload = company ? Object.fromEntries(Object.entries(profile).filter(([key, value]) => {
      const fields = key === 'employees' ? ['employeeMin', 'employeeMax']
        : key === 'revenue' ? ['revenueMin', 'revenueMax', 'currency', 'period'] : [key]
      return fields.some(field => values[field] !== initialValues[field])
        && JSON.stringify(value) !== JSON.stringify(company[key as keyof CompanyProfile])
    })) : profile
    if (company && !Object.keys(payload).length) {
      setLocalNotice('No changes to save.')
      return
    }
    setBusy(true)
    try { onSaved(await api<Company>(company ? `/companies/${company.id}` : '/companies', { method: company ? 'PATCH' : 'POST', body: JSON.stringify(payload) })) }
    catch (error) { setError(errorMessage(error)) } finally { setBusy(false) }
  }
  return <>
    <header className="page-header"><p className="eyebrow">Company intelligence</p><h1>{company ? 'Company profile' : 'Add company'}</h1><p className="muted">Give the analysis enough context to distinguish relevant threats.</p></header>
    {(notice || localNotice) && <p className="notice" role="status">{notice || localNotice}</p>}
    <form className="profile-form" onSubmit={save}><fieldset disabled={busy}>
      <section><h2>Identity</h2><div className="form-grid">
        {field('name', 'Company name')}{field('industry', 'Industry')}
        {listField('aliases', 'Other names')}{listField('domains', 'Domains')}
        {listField('countries', 'Countries')}<div className="technologies-field">{listField('technologies', 'Technologies')}</div>
      </div></section>
      <section><h2>Company size</h2><p className="muted">Leave unknown values blank. Approximate ranges can help match anonymous listings.</p><div className="form-grid">
        {field('employeeMin', 'Employees · minimum', undefined, true)}{field('employeeMax', 'Employees · maximum', undefined, true)}
        {field('revenueMin', 'Revenue · minimum', undefined, true)}{field('revenueMax', 'Revenue · maximum', undefined, true)}
        {field('currency', 'Revenue currency', 'For example, EUR or USD.')}{field('period', 'Revenue period', 'For example, 2025 or annual.')}
      </div></section>
      {error && <ErrorNotice message={error} />}
      <div className="form-footer"><p className="muted">Creating or changing this profile queues analysis against the collected posts.</p><Button primary type="submit" disabled={busy}>{busy ? 'Saving…' : company ? 'Save profile' : 'Create company'}</Button></div>
    </fieldset></form>
  </>
}
