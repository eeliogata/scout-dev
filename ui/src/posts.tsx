import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, dateTime, errorMessage, labels } from './api'
import { alertDisplayText } from './alertDisplay'
import { Badge, Button, EmptyState, ErrorNotice, Loading } from './components'
import { useResource } from './useResource'
import type { PostListItem, PostListPage, PostVersion } from './types'
import { TargetGroups } from './targets'

export function PostsPage() {
  const { data, error, refreshing, reload } = useResource<PostListPage>('/posts?limit=100')
  const [pagination, setPagination] = useState<{ first: PostListPage; items: PostListItem[]; next: string | null }>()
  const [busy, setBusy] = useState(false)
  const [pageError, setPageError] = useState('')
  const request = useRef<AbortController | null>(null)
  useEffect(() => {
    setBusy(false); setPageError('')
    return () => { request.current?.abort(); request.current = null }
  }, [data, refreshing])
  const extra = pagination?.first === data ? pagination : undefined
  const posts = [...(data?.items ?? []), ...(extra?.items ?? [])]
  const cursor = extra ? extra.next : data?.next_cursor
  async function loadMore() {
    if (!data || !cursor || refreshing || request.current) return
    const controller = new AbortController()
    request.current = controller; setBusy(true); setPageError('')
    try {
      const page = await api<PostListPage>('/posts?limit=100&cursor=' + encodeURIComponent(cursor), { signal: controller.signal })
      if (controller.signal.aborted) return
      const ids = new Set(posts.map(post => post.post_id))
      setPagination({ first: data, next: page.next_cursor, items: [...(extra?.items ?? []), ...page.items.filter(post => !ids.has(post.post_id))] })
    } catch (error) {
      if (!controller.signal.aborted) setPageError(errorMessage(error))
    } finally {
      if (!controller.signal.aborted) { request.current = null; setBusy(false) }
    }
  }
  return <>
    <header className="page-header"><p className="eyebrow">Collected intelligence</p><h1>All posts</h1><p className="muted">{data ? `${data.total_count} posts · Current version of each post` : 'Posts across all sources and companies'}</p>
      <div className="actions"><Button disabled={refreshing} onClick={reload}>{refreshing && data ? 'Refreshing…' : 'Refresh'}</Button></div>
    </header>
    {error && <ErrorNotice message={error} retry={reload} />}
    {!data && !error && <Loading />}
    {data && !posts.length && <EmptyState title="No posts collected"><p>Retained forum posts will appear here when collection finishes.</p></EmptyState>}
    {!!posts.length && <>
      <table className="alert-table posts-table"><caption className="sr-only">Current collected posts, newest saved versions first</caption>
        <thead><tr><th>Post</th><th>Category</th><th>Source</th><th>Published / collected</th></tr></thead>
        <tbody>{posts.map(post => <tr key={post.post_id}>
          <td className="title-cell"><Link className="alert-link" to={`/posts/${post.version_id}`}>{post.title || 'Untitled post'}</Link><p className="excerpt muted">{post.excerpt}</p>{post.embedding_ready === false && <small className="muted">Awaiting embeddings</small>}</td>
          <td className="category-cell"><Badge value={post.category} /></td>
          <td className="source-cell muted">{alertDisplayText(post.source_name)}</td>
          <td className="date-cell"><time dateTime={post.published_at || post.fetched_at}>{dateTime(post.published_at || post.fetched_at)}</time>{!post.published_at && <span> · Collected</span>}</td>
        </tr>)}</tbody>
      </table>
      <div className="list-footer"><span className="muted">{posts.length} of {data?.total_count} posts shown</span>{cursor && <Button disabled={busy || refreshing} onClick={loadMore}>{busy ? 'Loading…' : 'Load more'}</Button>}</div>
      {pageError && <ErrorNotice message={pageError} retry={loadMore} />}
    </>}
  </>
}

export function PostDetailPage() {
  const { versionId } = useParams()
  const { data, error, reload } = useResource<PostVersion>(`/post-versions/${versionId}`)
  if (!data) return <><Link className="back-link" to="/posts">← All posts</Link>{error ? <ErrorNotice message={error} retry={reload} /> : <Loading />}</>
  const { post, classification } = data
  return <>
    <Link className="back-link" to="/posts">← All posts</Link>
    {error && <ErrorNotice message={error} retry={reload} />}
    <header className="detail-header"><p className="eyebrow">Collected post</p><h1>{post.title || 'Untitled post'}</h1>
      <div className="metadata"><Badge value={classification.category} />{post.author && <span>By {post.author}</span>}{post.published_at && <span>Published {dateTime(post.published_at)}</span>}<span>Collected {dateTime(post.fetched_at)}</span></div>
    </header>
    <div className="post-reading detail-body">
      <section><h2>Original post</h2><a className="source-url" href={post.url} target="_blank" rel="noopener noreferrer">{post.url}</a><pre>{post.text}</pre></section>
      <section className="explanation"><h2>Why this post was retained</h2><p>{classification.reason}</p></section>
      <section><h2>Target claims</h2><TargetGroups version={data} /></section>
      <p className="muted">{labels[classification.category]} claims are attributed to the source. Retaining a post does not confirm its claims or identify an affected company.</p>
    </div>
  </>
}
