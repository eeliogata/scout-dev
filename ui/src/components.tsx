import { useId } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { labels } from './api'

export function Button({ className = '', primary, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { primary?: boolean }) {
  return <button className={`button ${primary ? 'primary' : ''} ${className}`} {...props} />
}
export function Badge({ value }: { value: string }) {
  return <span className={`badge ${value}`}>{labels[value] || value}</span>
}
export function ErrorNotice({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="notice error" role="alert"><span>{message}</span>{retry && <Button onClick={retry}>Try again</Button>}</div>
}
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><h2>{title}</h2>{children && <div className="muted">{children}</div>}</div>
}
export function Loading() { return <p className="loading muted" role="status">Loading…</p> }
export function Field({ label, hint, children }: { label: string; hint?: string; children: (id: string) => ReactNode }) {
  const id = useId()
  return <div className="field"><label htmlFor={id}>{label}</label>{children(id)}{hint && <small id={`${id}-hint`} className="muted">{hint}</small>}</div>
}
export function Facts({ title, items, heading: Heading = 'h2' }: { title: string; items: string[]; heading?: 'h2' | 'h4' }) {
  return <section className="fact-group"><Heading>{title}</Heading>{items.length ? <ul>{items.map((item, i) => <li key={i}>{item}</li>)}</ul> : <p className="muted">None recorded.</p>}</section>
}
