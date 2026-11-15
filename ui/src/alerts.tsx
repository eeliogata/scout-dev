import { isGuest } from './api'
import { TargetGroups } from './targets'
import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useLocation, useParams, useSearchParams } from 'react-router-dom'
import { useCompany } from './App'
import { api, dateTime, errorMessage, labels } from './api'
import { Badge, Button, EmptyState, ErrorNotice, Facts, Field, Loading } from './components'
import { alertDisplayText, companyDisplayName } from './alertDisplay'
import { AnalysisStatus } from './analysis'
import { useResource } from './useResource'
import type { Alert, AlertDetail, AlertStatus, Evidence, Page, PostVersion } from './types'

export function AlertsPage() {
  const { company } = useCompany()
  const [search, setSearch] = useSearchParams()
  const [revision, setRevision] = useState(0)
  const completed = useCallback(() => setRevision(value => value + 1), [])
  const status = search.get('status') ?? 'open'
  const severity = search.get('severity') ?? ''
  const query = new URLSearchParams({ limit: '20' })
  if (status) query.set('status', status)
  if (severity) query.set('severity', severity)
  return <>
    <header className="page-header header-actions"><div><p className="eyebrow">Company intelligence</p><h1>Alerts</h1><p className="muted">{companyDisplayName(company.name)}</p></div>
      {!isGuest() && <TelegramAction key={company.id} companyId={company.id} />}
    </header>
    <AnalysisStatus companyId={company.id} onCompleted={completed} />
    <div className="list-heading"><h2>Threat review</h2><div className="filters">
      <Field label="Status">{id => <select id={id} value={status} onChange={event => setSearch({ status: event.target.value, severity })}>
        <option value="">All statuses</option>{['open', 'resolved', 'dismissed_not_targeted'].map(value => <option key={value} value={value}>{labels[value]}</option>)}
      </select>}</Field>
      <Field label="Severity">{id => <select id={id} value={severity} onChange={event => setSearch({ status, severity: event.target.value })}>
        <option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map(value => <option key={value} value={value}>{labels[value]}</option>)}
      </select>}</Field>
    </div></div>
    <AlertList key={`${company.id}:${query}`} revision={revision} path={`/companies/${company.id}/alerts?${query}`} companyId={company.id} />
  </>
}

function TelegramAction({ companyId, alertId }: { companyId: string; alertId?: string }) {
  const [busy, setBusy] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)

  async function send() {
    if (pending.current) return
    pending.current = true
    setBusy(true)
    setSent(false)
    setError('')
    try {
      await api(alertId ? `/alerts/${alertId}/telegram` : `/companies/${companyId}/telegram/latest-alert`, { method: 'POST' })
      setSent(true)
    } catch (error) {
      setError(errorMessage(error))
    } finally {
      pending.current = false
      setBusy(false)
    }
  }

  return <section className="telegram-action" aria-label="Telegram notification">
    <Button onClick={send} disabled={busy}>{busy ? 'Sending…' : alertId ? 'Resend to Telegram' : 'Send latest alert to Telegram'}</Button>
    <details className="telegram-help"><summary>Delivery details</summary><p className="muted">{alertId ? 'Each click sends this alert as a new message to the configured Telegram chat.' : 'Sends this company’s newest alert to the configured Telegram chat, regardless of filters.'}</p></details>
    {sent && <p role="status">{alertId ? 'Alert sent to Telegram.' : 'Latest alert sent to Telegram.'}</p>}
    {error && <ErrorNotice message={error} />}
  </section>
}

function AlertList({ path, companyId, revision }: { path: string; companyId: string; revision: number }) {
  const location = useLocation()
  const { data, error, refreshing, reload } = useResource<Page<Alert>>(path, revision)
  const [pagination, setPagination] = useState<{ first: Page<Alert>; items: Alert[]; next: string | null }>()
  const [busy, setBusy] = useState(false)
  const [pageError, setPageError] = useState('')
  const pageRequest = useRef<AbortController | null>(null)
  useEffect(() => {
    setBusy(false)
    setPageError('')
    return () => {
      pageRequest.current?.abort()
      pageRequest.current = null
    }
  }, [path, data, refreshing, revision])

  if (error && !data) return <ErrorNotice message={error} retry={reload} />
  if (!data) return <Loading />
  const loadedPages = pagination?.first === data ? pagination : undefined
  const alerts = [...data.items, ...(loadedPages?.items ?? [])]
  const cursor = loadedPages ? loadedPages.next : data.next_cursor

  async function loadMore() {
    if (!data || !cursor || refreshing || pageRequest.current) return
    const controller = new AbortController()
    pageRequest.current = controller
    setBusy(true)
    setPageError('')
    try {
      const page = await api<Page<Alert>>(path + '&cursor=' + encodeURIComponent(cursor), { signal: controller.signal })
      if (controller.signal.aborted) return
      const ids = new Set(alerts.map(item => item.id))
      setPagination({
        first: data, next: page.next_cursor,
        items: [...(loadedPages?.items ?? []), ...page.items.filter(item => !ids.has(item.id))],
      })
    } catch (error) {
      if (!controller.signal.aborted) setPageError(errorMessage(error))
    } finally {
      if (!controller.signal.aborted) {
        pageRequest.current = null
        setBusy(false)
      }
    }
  }
  if (!alerts.length) return <EmptyState title="No alerts found">{error && <ErrorNotice message={error} retry={reload} />}<p>No alerts match these filters. Analysis may still be pending.</p></EmptyState>
  return <>
    {error && <ErrorNotice message={error} retry={reload} />}
    <table className="alert-table"><caption className="sr-only">Company alerts, newest first</caption>
      <thead><tr><th>Severity</th><th>Alert</th><th>Status</th><th>Last updated</th></tr></thead>
      <tbody>{alerts.map(alert => <tr key={alert.id}>
        <td className="severity-cell"><Badge value={alert.severity} /></td>
        <td className="title-cell"><Link className="alert-link" state={{ alertsSearch: location.search }} to={`/companies/${companyId}/alerts/${alert.id}`}>{alertDisplayText(alert.title)}</Link><p className="excerpt muted">{alertDisplayText(alert.explanation)}</p></td>
        <td className="status-cell"><Badge value={alert.status} /></td>
        <td className="date-cell"><time dateTime={alert.updated_at}>{dateTime(alert.updated_at)}</time></td>
      </tr>)}</tbody>
    </table>
    <div className="list-footer"><span className="muted">{alerts.length} alerts shown · Newest first</span>{cursor && <Button disabled={busy || refreshing} onClick={loadMore}>{busy ? 'Loading…' : 'Load more'}</Button>}</div>
    {pageError && <ErrorNotice message={pageError} retry={loadMore} />}
  </>
}

function EvidenceBlock({ evidence, matched }: { evidence: Evidence; matched?: string[] }) {
  const [expanded, setExpanded] = useState(false)
  return <article className="evidence-block">
    <div className="section-label">Evidence</div>
    <blockquote>{evidence.quote}</blockquote>
    <details onToggle={event => setExpanded(event.currentTarget.open)}><summary>Original post and source</summary>
      {expanded && <OriginalPost versionId={evidence.post_version_id} matched={matched} />}
    </details>
  </article>
}

function OriginalPost({ versionId, matched }: { versionId: string; matched?: string[] }) {
  const { data, error, reload } = useResource<PostVersion>(`/post-versions/${versionId}`)
  if (error && !data) return <ErrorNotice message={error} retry={reload} />
  if (!data) return <Loading />
  const post = data.post
  return <div className="original-post">
    {error && <ErrorNotice message={error} retry={reload} />}
    <h3>{post.title || 'Untitled post'}</h3>
    <p className="muted">{post.author ? `By ${post.author} · ` : ''}{post.published_at ? `Published ${dateTime(post.published_at)} · ` : ''}Collected {dateTime(post.fetched_at)}</p>
    <a href={post.url} target="_blank" rel="noopener noreferrer">Open source ↗</a>
    <pre>{post.text}</pre>
    <section><h3>Target claims</h3><TargetGroups version={data} matched={matched} /></section>
  </div>
}

export function DetailPage() {
  const location = useLocation()
  const reviewHeading = useRef<HTMLHeadingElement>(null)
  const { company } = useCompany()
  const { alertId } = useParams()
  const { data, error, reload } = useResource<AlertDetail>(`/alerts/${alertId}`)
  const [target, setTarget] = useState<AlertStatus | null>(null)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [notice, setNotice] = useState('')
  useEffect(() => { setTarget(null); setReason(''); setNotice(''); setSaveError('') }, [alertId])
  if (error && !data) return <ErrorNotice message={error} retry={reload} />
  if (!data) return <Loading />
  const alert = data.alert
  if (alert.company_id !== company.id) return <EmptyState title="This alert belongs to another company"><Link to={`/companies/${alert.company_id}/alerts/${alert.id}`}>Open the correct company</Link></EmptyState>
  async function changeStatus(event: FormEvent) {
    event.preventDefault(); setBusy(true); setSaveError('')
    try {
      await api(`/alerts/${alertId}/status`, { method: 'PATCH', body: JSON.stringify({ status: target, reason: reason.trim() }) })
      setNotice(`Alert marked ${labels[target!].toLowerCase()}.`); setTarget(null); setReason(''); reviewHeading.current?.focus(); reload()
    } catch (error) { setSaveError(errorMessage(error)) } finally { setBusy(false) }
  }
  return <>
    <Link className="back-link" to={`/companies/${company.id}/alerts${location.state?.alertsSearch || ''}`}>← All alerts</Link>
    <header className="page-header detail-header"><p className="eyebrow">{companyDisplayName(company.name)}</p><h1>{alertDisplayText(alert.title)}</h1>
      <div className="metadata"><Badge value={alert.severity} /><Badge value={alert.status} /><span>{labels[alert.category]}</span><time dateTime={alert.updated_at}>Updated {dateTime(alert.updated_at)}</time></div>
      {!isGuest() && <TelegramAction key={alert.id} companyId={company.id} alertId={alert.id} />}
    </header>
    {error && <ErrorNotice message={error} retry={reload} />}
    {notice && <p role="status" className="notice">{notice}</p>}
    <div className="detail-grid"><div className="detail-body">
      <section className="explanation"><h2>Why this matters</h2><p>{alertDisplayText(alert.explanation)}</p><p className="muted">Assessment confidence: {Math.round(alert.confidence * 100)}%. This describes the assessment, not the probability of a breach.</p></section>
      <section><h2>Supporting evidence</h2>{alert.evidence.map((evidence, index) => <EvidenceBlock key={`${evidence.post_version_id}:${index}`} evidence={evidence} matched={alert.matched_target_ids} />)}</section>
      <div className="facts"><Facts title="Matching attributes" items={alert.matching_attributes} /><Facts title="Conflicting attributes" items={alert.conflicting_attributes} /><Facts title="Missing information" items={alert.missing_information} /></div>
      <Facts title="Suggested actions" items={alert.suggested_actions.map(alertDisplayText)} />
    </div>{!isGuest() && <aside className="review-panel" aria-label="Review alert">
      <h2 ref={reviewHeading} tabIndex={-1}>Review decision</h2><p className="muted">Record your assessment for the team.</p>
      <div className="review-actions">{(['resolved', 'dismissed_not_targeted', 'open'] as AlertStatus[]).filter(value => value !== alert.status).map(value => <Button key={value} disabled={busy} onClick={() => { setTarget(value); setSaveError(''); setNotice('') }}>{value === 'open' ? 'Reopen' : value === 'resolved' ? 'Resolve' : 'Not our company'}</Button>)}</div>
      {target && <form onSubmit={changeStatus}><h3>Mark as {labels[target].toLowerCase()}</h3>
        <Field label="Reason">{id => <textarea id={id} value={reason} onChange={e => setReason(e.target.value)} rows={4} required autoFocus />}</Field>
        {saveError && <ErrorNotice message={saveError} />}
        <div className="actions"><Button primary type="submit" disabled={busy || !reason.trim()}>{busy ? 'Saving…' : 'Save decision'}</Button><Button type="button" disabled={busy} onClick={() => setTarget(null)}>Cancel</Button></div>
      </form>}
    </aside>}</div>
    <section className="history"><h2>Review history</h2>
      {!data.events.length ? <p className="muted">No review decisions yet.</p> : <ol>{[...data.events].sort((a, b) => a.created_at.localeCompare(b.created_at)).map(event => <li key={event.id}>
        <div className="metadata"><strong>{event.actor === 'user' ? 'Team member' : 'Analysis model'}</strong><span>{labels[event.previous_status]} → {labels[event.status]}</span><time dateTime={event.created_at}>{dateTime(event.created_at)}</time></div>
        <p>{event.reason}</p>{event.note && event.note !== event.reason && <p className="muted">{event.note}</p>}
        {event.evidence.map((evidence, index) => <EvidenceBlock key={`${event.id}:${index}`} evidence={evidence} />)}
      </li>)}</ol>}
    </section>
  </>
}
