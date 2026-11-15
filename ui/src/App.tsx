import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, NavLink, Navigate, Outlet, Route, Routes, useLocation, useNavigate, useOutletContext, useParams } from 'react-router-dom'
import { api, ApiError, errorMessage, guestStorage, isGuest, keyStorage } from './api'
import { companyDisplayName } from './alertDisplay'
import { Button, EmptyState, ErrorNotice, Field, Loading } from './components'
import { useResource } from './useResource'
import { AlertsPage, DetailPage } from './alerts'
import { ProfileForm } from './profile'
import { PostsPage, PostDetailPage } from './posts'
import type { Company, Page } from './types'

export type CompanyContext = { company: Company; refreshCompanies: () => void; refreshCompany: () => void }
export const useCompany = () => useOutletContext<CompanyContext>()

function AccessScreen({ connected }: { connected: () => void }) {
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{ message: string; invalidKey: boolean } | null>(null)
  const { data: guestAccess } = useResource<{ enabled: boolean }>('/guest-access')
  async function guestLogin() {
    if (busy) return
    setBusy(true); setError(null); sessionStorage.removeItem(keyStorage); sessionStorage.setItem(guestStorage, '1')
    try { await api('/session'); connected() }
    catch (error) { sessionStorage.removeItem(guestStorage); setError({ message: errorMessage(error), invalidKey: false }) }
    finally { setBusy(false) }
  }
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy || !key.trim()) return
    setBusy(true); setError(null)
    try {
      await api<Page<Company>>('/companies?limit=1', {}, key.trim())
      sessionStorage.removeItem(guestStorage); sessionStorage.setItem(keyStorage, key.trim()); connected()
    } catch (error) {
      setError({ message: errorMessage(error), invalidKey: error instanceof ApiError && error.status === 401 })
    } finally { setBusy(false) }
  }
  return <><a className="skip-link" href="#main">Skip to content</a><main id="main" tabIndex={-1} className="access"><div className="access-form">
    <div className="wordmark">scout.dev<span>Threat review</span></div>
    <header>
      <h1 id="access-heading">Connect to your workspace</h1>
      <p className="muted">Review company threats and the evidence behind them.</p>
    </header>
    <form onSubmit={submit} aria-labelledby="access-heading" aria-busy={busy}>
      <Field label="Access key" hint="Use your team's shared API key. It stays in this browser tab until you disconnect or close the tab.">{id => <input
        id={id} type="password" value={key} onChange={e => { setKey(e.target.value); setError(null) }}
        required autoComplete="off" autoFocus readOnly={busy} spellCheck={false}
        aria-describedby={`${id}-hint${error ? ' access-error' : ''}`} aria-invalid={error?.invalidKey || undefined}
      />}</Field>
      {error && <div id="access-error"><ErrorNotice message={error.message} /></div>}
      <Button primary disabled={busy || !key.trim()} type="submit">{busy ? 'Connecting…' : 'Connect to workspace'}</Button>
    </form>
    {guestAccess?.enabled && <div className="access-guest">
      <Button disabled={busy} onClick={guestLogin}>Continue as guest</Button>
      <p className="muted">Browse posts and alerts with read-only access.</p>
    </div>}
    <span className="sr-only" role="status">{busy ? 'Connecting to workspace…' : ''}</span>
  </div></main></>
}

function CompanyLayout({ refreshCompanies }: { refreshCompanies: () => void }) {
  const { companyId } = useParams()
  const { data, error, reload } = useResource<Company>(`/companies/${companyId}`)
  if (error && !data) return <ErrorNotice message={error} retry={reload} />
  if (!data) return <Loading />
  return <div key={companyId}>{error && <ErrorNotice message={error} retry={reload} />}<Outlet context={{ company: data, refreshCompanies, refreshCompany: reload } satisfies CompanyContext} /></div>
}

function Workspace({ disconnect }: { disconnect: () => void }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const [companies, setCompanies] = useState<Company[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  const refreshCompanies = () => setRevision(value => value + 1)
  const location = useLocation()
  const navigate = useNavigate()
  const routeCompanyId = location.pathname.match(/^\/companies\/([^/]+)/)?.[1]
  const [rememberedId, setRememberedId] = useState(() => sessionStorage.getItem('junction-company'))
  const selectedId = routeCompanyId && routeCompanyId !== 'new' ? routeCompanyId : rememberedId
  const selected = companies.find(company => company.id === selectedId)
  useEffect(() => {
    if (selected) { sessionStorage.setItem('junction-company', selected.id); setRememberedId(selected.id) }
    else if (!loading && !error && rememberedId && !companies.some(company => company.id === rememberedId)) {
      sessionStorage.removeItem('junction-company'); setRememberedId(null)
    }
  }, [selected, loading, error, rememberedId, companies])
  useEffect(() => {
    setMenuOpen(false)
    window.scrollTo(0, 0)
    document.getElementById('main')?.focus({ preventScroll: true })
  }, [location.pathname])
  useEffect(() => {
    const controller = new AbortController()
    async function load() {
      setError('')
      try {
        const all: Company[] = []
        let cursor: string | null = null
        do {
          const page: Page<Company> = await api(`/companies?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { signal: controller.signal })
          all.push(...page.items); cursor = page.next_cursor
        } while (cursor)
        if (!controller.signal.aborted) { setCompanies(all); setLoading(false) }
      } catch (error) {
        if (!controller.signal.aborted) { setError(errorMessage(error)); setLoading(false) }
      }
    }
    void load()
    return () => controller.abort()
  }, [revision])
  const defaultCompany = companies.find(company => company.domains.includes('tatry-lakeside.example')) ?? companies[0]
  const companyPath = selected ? `/companies/${selected.id}` : null
  return <div className="workspace">
    <a className="skip-link" href="#main">Skip to content</a>
    <aside className={`sidebar ${menuOpen ? 'menu-open' : ''}`}>
      <Link className="wordmark" to="/">scout.dev<span>Threat review</span></Link>
      <div className="mobile-tools">{isGuest() && <span className="muted">Guest · Read-only</span>}<Button aria-expanded={menuOpen} aria-controls="workspace-sidebar" onClick={() => setMenuOpen(value => !value)}>Menu</Button></div>
      <div id="workspace-sidebar" className="sidebar-controls">
      <Field label="Company">{id => <select id={id} value={selected?.id || ''} onChange={e => { if (e.target.value) navigate(`/companies/${e.target.value}/alerts`) }}>
        <option value="" disabled>{loading ? 'Loading…' : 'Select company'}</option>
        {companies.map(company => <option key={company.id} value={company.id}>{companyDisplayName(company.name)}</option>)}
      </select>}</Field>
      </div>
      <nav aria-label="Main navigation">
        {companyPath && <><NavLink to={`${companyPath}/alerts`}>Alerts</NavLink>{!isGuest() && <NavLink className="secondary-nav" to={`${companyPath}/profile`}>Company profile</NavLink>}</>}
        <NavLink to="/posts">All posts</NavLink>
        {!isGuest() && <NavLink className="secondary-nav" to="/companies/new">Add company</NavLink>}
      </nav>
      <div className="sidebar-footer"><span className="muted">{isGuest() ? 'Guest · Read-only' : 'Shared workspace'}</span><Button onClick={disconnect}>Disconnect</Button></div>
    </aside>
    <main id="main" tabIndex={-1} className="main"><div className="content">
      {error && <ErrorNotice message={error} retry={refreshCompanies} />}
      {loading ? <Loading /> : <Routes>
        <Route path="/posts" element={<PostsPage />} />
        <Route path="/posts/:versionId" element={<PostDetailPage />} />
        <Route path="/" element={companies.length ? <Navigate replace to={`/companies/${selected?.id || defaultCompany.id}/alerts`} /> : error ? null : isGuest() ? <Navigate replace to="/posts" /> : <EmptyState title="Add your first company"><p>Create a profile to start reviewing relevant threats.</p><Link className="button primary" to="/companies/new">Add company</Link></EmptyState>} />
        <Route path="/companies/new" element={isGuest() ? <Navigate replace to="/posts" /> : <ProfileForm onSaved={company => { refreshCompanies(); navigate(`/companies/${company.id}/profile`, { state: { notice: 'Company created. Analysis queued.' } }) }} />} />
        <Route path="/companies/:companyId" element={<CompanyLayout refreshCompanies={refreshCompanies} />}>
          <Route index element={<Navigate replace to="alerts" />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="alerts/:alertId" element={<DetailPage />} />
          <Route path="profile" element={isGuest() ? <Navigate replace to="../alerts" /> : <CompanyProfile />} />
        </Route>
        <Route path="*" element={<EmptyState title="Page not found"><Link to="/">Return to workspace</Link></EmptyState>} />
      </Routes>}
    </div></main>
  </div>
}

function CompanyProfile() {
  const { company, refreshCompany, refreshCompanies } = useCompany()
  const navigate = useNavigate()
  const location = useLocation()
  const [notice, setNotice] = useState('')
  useEffect(() => {
    if (!location.state?.notice) return
    setNotice(location.state.notice)
    navigate({ pathname: location.pathname, search: location.search, hash: location.hash }, { replace: true, state: null })
  }, [location, navigate])
  return <ProfileForm
    key={company.id + ':' + company.profile_version}
    company={company}
    notice={notice}
    onDismissNotice={() => setNotice('')}
    onSaved={saved => {
      setNotice(saved.profile_version === company.profile_version ? 'No changes to save.' : 'Profile saved. Analysis queued.')
      refreshCompany()
      refreshCompanies()
    }}
  />
}

export function App() {
  const [connected, setConnected] = useState(!!sessionStorage.getItem(keyStorage) || isGuest())
  useEffect(() => {
    const listener = () => setConnected(false)
    window.addEventListener('junction-disconnected', listener)
    return () => window.removeEventListener('junction-disconnected', listener)
  }, [])
  return connected ? <Workspace disconnect={() => { sessionStorage.removeItem(keyStorage); sessionStorage.removeItem(guestStorage); setConnected(false) }} /> : <AccessScreen connected={() => setConnected(true)} />
}
