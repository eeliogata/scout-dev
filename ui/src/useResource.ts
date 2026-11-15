import { useEffect, useState } from 'react'
import { api, errorMessage } from './api'

export function useResource<T>(path: string, revision = 0) {
  const [state, setState] = useState<{ path: string; revision: number; retry: number; data?: T; error?: string }>()
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    api<T>(path, { signal: controller.signal })
      .then(data => {
        if (!controller.signal.aborted) setState({ path, revision, retry, data })
      })
      .catch(error => {
        if (!controller.signal.aborted) setState(current => ({
          path, revision, retry, data: current?.path === path ? current.data : undefined, error: errorMessage(error),
        }))
      })
    return () => controller.abort()
  }, [path, revision, retry])
  const current = state?.path === path ? state : undefined
  const refreshing = !current || current.revision !== revision || current.retry !== retry
  return {
    data: current?.data,
    error: refreshing ? undefined : current?.error,
    refreshing,
    reload: () => setRetry(value => value + 1),
  }
}
