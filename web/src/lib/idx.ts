import { ApiError, apiFetch } from '@/lib/api'

/**
 * What the server says the sign-in screen is. The client renders this and owns
 * no sign-in copy of its own: titles, labels, fields, choices and alternative
 * actions all arrive in `remediation[0].ui`.
 */
export type IdxIcon = 'password' | 'passkey'

export type IdxUiField = {
  name: string
  kind: 'email' | 'password'
  label: string
  autocomplete: string
  required: boolean
}

export type IdxUiOption = {
  id: string
  label: string
  description?: string
  icon: IdxIcon
}

export type IdxUiAlternative = {
  label: string
  icon?: IdxIcon
  action: 'passkey' | 'switch-method' | 'cancel' | 'skip-location'
  placement: 'before' | 'after'
  variant: 'outline' | 'link'
}

export type IdxUiMessages = {
  invalid_credentials: string
  passkey_failed: string
  rate_limited: string
  denied: string
  unavailable: string
  forbidden_app: string
  incomplete: string
  location_denied: string
  location_outside: string
  location_inaccurate: string
  location_blocked: string
}

export type IdxUi = {
  title: string
  description?: string
  badge?: IdxIcon
  fields: IdxUiField[]
  options: IdxUiOption[]
  submit?: { label: string }
  action: 'identify' | 'select-authenticator' | 'opaque-password' | 'passkey' | 'share-location'
  alternatives: IdxUiAlternative[]
  separator?: string
  messages: IdxUiMessages
}

type IdxRemediation = {
  name: string
  href?: string
  ui?: IdxUi
}

type IdxEnvelope = {
  stateHandle: string
  remediation?: { value?: IdxRemediation[] }
  user?: { value?: { identifier?: string } }
  app?: { value?: { label?: string } }
}

export type IdxState = {
  stateHandle: string
  /** Remediation name from the server (identify, challenge-authenticator, ...). */
  step: string
  ui: IdxUi
  appLabel: string
  identifier: string | null
}

function toState(body: IdxEnvelope): IdxState {
  const remediation = body.remediation?.value?.[0]
  if (!remediation?.ui) throw new Error('The server sent no screen definition')
  return {
    stateHandle: body.stateHandle,
    step: remediation.name,
    ui: remediation.ui,
    appLabel: body.app?.value?.label ?? 'WorkPass',
    identifier: body.user?.value?.identifier ?? null,
  }
}

function post(path: string, body: unknown): Promise<IdxEnvelope> {
  return apiFetch<IdxEnvelope>(path, { method: 'POST', body: JSON.stringify(body) })
}

/** Begin (or restart) a transaction for a signed authorization request. */
export async function idxIntrospect(oauthQuery?: string, options?: { skipLocation?: boolean }): Promise<IdxState> {
  return toState(await post('/idp/idx/introspect', { ...(oauthQuery ? { oauthQuery } : {}), ...(options?.skipLocation ? { skipLocation: true } : {}) }))
}

/** Submit the email. Unknown addresses get a plausible answer, never an error. */
export async function idxIdentify(
  handle: string,
  identifier: string,
  oauthQuery?: string,
): Promise<IdxState> {
  try {
    return toState(await post('/idp/idx/identify', { identifier, stateHandle: handle }))
  } catch (error) {
    // An expired handle restarts the transaction once, transparently.
    if (error instanceof ApiError && error.status === 401) {
      const fresh = await idxIntrospect(oauthQuery)
      return toState(await post('/idp/idx/identify', { identifier, stateHandle: fresh.stateHandle }))
    }
    throw error
  }
}

/** Pick an authenticator, or omit the id to be shown the choice again. */
export async function idxChallenge(handle: string, authenticatorId?: string): Promise<IdxState> {
  return toState(
    await post('/idp/idx/challenge', {
      stateHandle: handle,
      ...(authenticatorId ? { authenticator: { id: authenticatorId } } : {}),
    }),
  )
}
