import { isGuest } from './api'
import { useEffect, useRef, useState } from 'react'
import { api, dateTime, errorMessage } from './api'
import { Badge, Button, ErrorNotice } from './components'
import type { Job, Page } from './types'

function isActive(job: Job | null) {
  return job?.state === 'queued' || job?.state === 'running'
}

function RunCoverage({ job }: { job: Job }) {
  const coverage = job.coverage ?? {}
  const counts = [
    ['Selected', coverage.selected ?? job.total_count],
    ['Deferred', coverage.deferred],
    ['Awaiting embeddings', coverage.pending_embeddings],
    ['Superseded before selection', coverage.superseded],
    ['Superseded during run', coverage.superseded_assignments],
    ['Excluded', coverage.excluded],
  ] as const
  const recorded = counts.filter(([, count]) => typeof count === 'number')
  const reviewed = Math.max(0, job.processed_count - (coverage.superseded_assignments ?? 0))
  return <>
    <p className="muted">{job.analysis_scope === 'daily_candidates' ? 'Daily candidate selection' : 'Full corpus snapshot'} · Requested {dateTime(job.created_at)}</p>
    <p className="muted">{reviewed}{job.total_count !== null ? ` of ${job.total_count}` : ''} selected post versions reviewed</p>
    {!!recorded.length && <ul className="analysis-coverage muted" aria-label="Run coverage">{recorded.map(([label, count]) =>
      <li key={label}>{label}: {count}</li>,
    )}</ul>}
    {coverage.candidate_limit_reached && <p className="muted">Search reached its candidate limit. Additional relevant posts may be deferred.</p>}
  </>
}

export function AnalysisStatus({ companyId, onCompleted }: { companyId: string; onCompleted: () => void }) {
  const [job, setJob] = useState<Job | null>(null)
  const [requestedJobId, setRequestedJobId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [submissionError, setSubmissionError] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [revision, setRevision] = useState(0)
  const submission = useRef<AbortController | null>(null)
  const refreshedJobs = useRef(new Set<string>())

  useEffect(() => () => submission.current?.abort(), [])
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    async function poll() {
      try {
        const options = { signal: controller.signal }
        const current = requestedJobId
          ? await api<Job>(`/jobs/${requestedJobId}`, options)
          : (await api<Page<Job>>(`/companies/${companyId}/analysis-jobs?limit=1`, options)).items[0] ?? null
        if (controller.signal.aborted) return

        setJob(current)
        setError('')
        setLoading(false)
        if (current && !isActive(current)) {
          const signature = `${current.id}:${current.state}:${current.finished_at}`
          if (!refreshedJobs.current.has(signature)) {
            refreshedJobs.current.add(signature)
            onCompleted()
          }
          if (requestedJobId) setRequestedJobId(null)
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          setError(errorMessage(error))
          setLoading(false)
        }
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 3000)
      }
    }
    void poll()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [companyId, requestedJobId, revision, onCompleted])

  const canRun = !busy && !loading && !isActive(job) && !requestedJobId

  async function run(retry = false) {
    if (submission.current || !canRun) return
    const controller = new AbortController()
    submission.current = controller
    setBusy(true)
    setSubmissionError('')
    try {
      const { job_id } = await api<{ job_id: string }>(retry && job ? `/jobs/${job.id}/retry` : `/companies/${companyId}/analysis-runs`, {
        method: 'POST', signal: controller.signal,
      })
      if (controller.signal.aborted) return
      setJob(null)
      setError('')
      setLoading(true)
      setRequestedJobId(job_id)
    } catch (error) {
      if (!controller.signal.aborted) setSubmissionError(errorMessage(error))
    } finally {
      if (!controller.signal.aborted) {
        submission.current = null
        setBusy(false)
      }
    }
  }
  return <section className="analysis-strip" aria-label="Latest analysis">
    <div className="analysis-top"><div><span className="section-label">Latest analysis</span>{job && <Badge value={job.state} />}</div>
      {!isGuest() && <div className="actions">{job && (job.state === 'failed' || job.state === 'incomplete') && <Button onClick={() => run(true)} disabled={!canRun}>Retry run</Button>}<Button onClick={() => run()} disabled={!canRun}>{busy ? 'Queuing…' : 'Run full analysis'}</Button></div>}
    </div>
    <div aria-live="polite">
      {loading ? <p className="muted">Checking analysis status…</p> : job ? <>
        <details className="analysis-details"><summary>Scope and coverage</summary><RunCoverage job={job} />{job.state === 'succeeded' && <p className="muted">This run is complete. Other posts or earlier runs may still need review.</p>}</details>
        {job.state === 'queued' && <p className="muted">Waiting for the analysis worker.</p>}
        {job.state === 'incomplete' && <p className="muted">Analysis is incomplete. Review coverage before drawing conclusions.</p>}
        {job.error && <ErrorNotice message={job.error} />}
      </> : !error && <p className="muted">No analysis has been requested for this company.</p>}
    </div>
    {submissionError && <ErrorNotice message={submissionError} />}
    {error && <ErrorNotice message={error} retry={() => {
      setLoading(true)
      setRevision(value => value + 1)
    }} />}
  </section>
}
