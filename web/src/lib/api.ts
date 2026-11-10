export class ApiError extends Error {
  readonly status: number
  readonly body: unknown

  constructor(status: number, message: string, body: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

function errorMessage(body: unknown, status: number): string {
  if (body && typeof body === 'object') {
    const { error, message, errorSummary } = body as {
      error?: unknown
      message?: unknown
      errorSummary?: unknown
    }
    if (typeof errorSummary === 'string' && errorSummary) return errorSummary
    if (typeof message === 'string' && message) return message
    if (typeof error === 'string' && error) return error
  }
  return `Request failed (${status})`
}

/**
 * Same-origin JSON request to the backend Worker. Mutating requests carry the
 * browser Origin header automatically, which the backend's exact-origin checks
 * require; credentials stay in the HttpOnly session cookie.
 */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  const text = await response.text()
  let body: unknown = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }
  if (!response.ok) {
    throw new ApiError(response.status, errorMessage(body, response.status), body)
  }
  return body as T
}
