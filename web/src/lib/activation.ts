import { getOpaqueConfig, OpaqueClient, OpaqueID, RegistrationResponse, ScryptMemHardFn } from '@cloudflare/opaque-ts'
import { ApiError, apiFetch } from '@/lib/api'

const config = getOpaqueConfig(OpaqueID.OPAQUE_P256)

function toWire(bytes: number[]): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function fromWire(wire: string): number[] {
  const binary = atob(wire.replace(/-/g, '+').replace(/_/g, '/'))
  return Array.from(binary, (char) => char.charCodeAt(0))
}

export type PasswordRules = {
  minLength: number
  minUpper: number
  minLower: number
  minDigit: number
  minSymbol: number
  symbolSet: string
  checkHibp: boolean
}

/** The whole activation screen, defined by the server. */
export type ActivationUi = {
  title: string
  description: string
  requirements: string[]
  rules: PasswordRules
  fields: Array<{ name: 'password' | 'confirm'; label: string; autocomplete: string }>
  submit: { label: string }
  done: { title: string; description: string; action: string }
  messages: {
    mismatch: string
    min_length: string
    min_upper: string
    min_lower: string
    min_digit: string
    min_symbol: string
    invalid_link: string
    rate_limited: string
    unavailable: string
  }
}

export type ActivationInspect = { email: string; expiresAt: string; ui: ActivationUi }

export function inspectActivation(token: string): Promise<ActivationInspect> {
  return apiFetch<ActivationInspect>('/api/activation/inspect', {
    method: 'POST',
    body: JSON.stringify({ token }),
  })
}

/** Checks in the same order as the server-provided requirement labels. */
export function passwordRequirementChecks(password: string, rules: PasswordRules) {
  const count = (pattern: RegExp) => (password.match(pattern) ?? []).length
  const symbols = rules.symbolSet.split('')
  return [
    { key: 'min_length' as const, required: true, satisfied: password.length >= rules.minLength },
    { key: 'min_upper' as const, required: rules.minUpper > 0, satisfied: count(/[A-Z]/g) >= rules.minUpper },
    { key: 'min_lower' as const, required: rules.minLower > 0, satisfied: count(/[a-z]/g) >= rules.minLower },
    { key: 'min_digit' as const, required: rules.minDigit > 0, satisfied: count(/[0-9]/g) >= rules.minDigit },
    {
      key: 'min_symbol' as const,
      required: rules.minSymbol > 0,
      satisfied: password.split('').filter((char) => symbols.includes(char)).length >= rules.minSymbol,
    },
  ].filter((check) => check.required)
}

/**
 * Check a candidate against the rules the server sent. OPAQUE keeps the
 * password from the server, so this is the only place the rules can run; the
 * server delivers them, the browser applies them. Returns the first failing
 * message, or null.
 */
export function checkPassword(password: string, ui: ActivationUi): string | null {
  const failed = passwordRequirementChecks(password, ui.rules).find((check) => !check.satisfied)
  return failed ? ui.messages[failed.key] : null
}

export type ActivationResult = 'ok' | 'invalid_link' | 'rate_limited' | 'unavailable'

/** OPAQUE registration for an activation link; the password never leaves the browser. */
export async function activateAccount(token: string, password: string): Promise<ActivationResult> {
  try {
    const client = new OpaqueClient(config, ScryptMemHardFn)
    const request = await client.registerInit(password)
    if (request instanceof Error) return 'unavailable'
    const start = await apiFetch<{
      registrationResponse: string
      credentialIdentifier: string
      serverIdentity: string
    }>('/api/activation/register/start', {
      method: 'POST',
      body: JSON.stringify({ token, registrationRequest: toWire(request.serialize()) }),
    })
    const finished = await client.registerFinish(
      RegistrationResponse.deserialize(config, fromWire(start.registrationResponse)),
      start.serverIdentity,
      start.credentialIdentifier,
    )
    if (finished instanceof Error) return 'unavailable'
    await apiFetch('/api/activation/register/finish', {
      method: 'POST',
      body: JSON.stringify({ token, record: toWire(finished.record.serialize()) }),
    })
    return 'ok'
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.status === 429) return 'rate_limited'
      if (error.status === 404 || error.status === 400) return 'invalid_link'
    }
    return 'unavailable'
  }
}
