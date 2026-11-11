// Parameters that only exist to sign the request. They never belong in the address bar.
const SIGNING_PARAMS = new Set(['exp', 'ba_iat', 'ba_param', 'sig', 'fingerprint_event_id'])

// The order every OAuth2 client sends: alphabetical, with the scope last.
const LEADING = [
  'client_id',
  'code_challenge',
  'code_challenge_method',
  'nonce',
  'redirect_uri',
  'response_type',
  'state',
]

/** The path the browser shows for the sign-in screen. */
export const AUTHORIZE_PATH = '/oauth2/v1/authorize'

/**
 * The address of a sign-in request as an app would have sent it:
 * `/oauth2/v1/authorize?client_id=…&scope=openid%20profile…`. The signature
 * and expiry are left out; reloading this address makes the server start a
 * fresh signed request, so it is safe to show and to reload.
 */
export function authorizeSearchFromSignedQuery(signedQuery: string): string | null {
  const params = new URLSearchParams(signedQuery)
  if (!params.get('client_id')) return null

  const entries: Array<[string, string]> = []
  for (const key of LEADING) {
    const value = params.get(key)
    if (value !== null) entries.push([key, value])
  }
  const rest = [...new Set(params.keys())]
    .filter((key) => !LEADING.includes(key) && key !== 'scope' && !SIGNING_PARAMS.has(key))
    .sort()
  for (const key of rest) entries.push([key, params.get(key) ?? ''])
  const scope = params.get('scope')
  if (scope !== null) entries.push(['scope', scope])

  // encodeURIComponent writes a space as %20, the form every provider shows.
  return `?${entries.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&')}`
}

const STORE_KEY = 'authorize-url-map'

function readMap(): Record<string, string> {
  try {
    return JSON.parse(window.sessionStorage.getItem(STORE_KEY) ?? '{}') as Record<string, string>
  } catch {
    return {}
  }
}

/**
 * Remember which signed request a shown address stands for. The router parses
 * its own address again after a navigation or a hot reload; without this it
 * would find an address with no signature and restart the sign-in, forever.
 */
export function rememberSignedQuery(shownSearch: string, signedQuery: string): void {
  try {
    window.sessionStorage.setItem(STORE_KEY, JSON.stringify({ ...readMap(), [shownSearch]: signedQuery }))
  } catch {
    /* storage unavailable: the address still works through the server */
  }
}

export function recallSignedQuery(shownSearch: string): string | null {
  return readMap()[shownSearch] ?? null
}
