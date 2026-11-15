export const keyStorage = 'junction-access-key'
export const guestStorage = 'scout-guest'
export const isGuest = () => sessionStorage.getItem(guestStorage) === '1'

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message) }
}

export async function api<T>(path: string, init: RequestInit = {}, key = sessionStorage.getItem(keyStorage) || ''): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(key ? { 'X-API-Key': key } : isGuest() ? { 'X-Guest-Access': '1' } : {}), ...init.headers },
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new Error('Cannot reach the server. Check your connection and try again.')
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    const detail = body?.detail
    const message = typeof detail === 'string' ? detail : Array.isArray(detail)
      ? detail.map((item: { loc?: string[]; msg?: string }) => `${item.loc?.slice(1).join('.') || 'Input'}: ${item.msg}`).join('; ')
      : `Request failed (${response.status}). Please try again.`
    if (response.status === 401 && (key === sessionStorage.getItem(keyStorage) || isGuest())) {
      sessionStorage.removeItem(keyStorage)
      sessionStorage.removeItem(guestStorage)
      window.dispatchEvent(new Event('junction-disconnected'))
    }
    throw new ApiError(message, response.status)
  }
  return response.json()
}

export const errorMessage = (error: unknown) => error instanceof Error ? error.message : 'Something went wrong. Please try again.'
export const dateTime = (value: string) => new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
export const labels: Record<string, string> = {
  open: 'Open', resolved: 'Resolved', dismissed_not_targeted: 'Not our company',
  low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical',
  queued: 'Queued', running: 'Running', succeeded: 'Completed', failed: 'Failed', incomplete: 'Incomplete',
  access_sale: 'Access sale', credentials: 'Credentials', data_leak: 'Data leak', exploitation: 'Exploitation', other: 'Other',
}
