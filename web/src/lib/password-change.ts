import { getOpaqueConfig, KE2, OpaqueClient, OpaqueID, RegistrationResponse, ScryptMemHardFn } from '@cloudflare/opaque-ts'
import { ApiError, apiFetch } from '@/lib/api'
import { fromWire, normalizeIdentifier, toWire } from '@/lib/opaque'
import type { PasswordRules } from '@/lib/activation'

const config = getOpaqueConfig(OpaqueID.OPAQUE_P256)

export type ChangeOutcome = 'ok' | 'wrong_password' | 'rate_limited' | 'expired' | 'unavailable'

export type PasswordChangeSession = { rules: PasswordRules; email: string }

/** Why a candidate fails the rules the server delivered, in Korean; null when it passes. */
export function passwordProblem(password: string, rules: PasswordRules): string | null {
  const count = (pattern: RegExp) => (password.match(pattern) ?? []).length
  if (password.length < rules.minLength) return `${rules.minLength}자 이상이어야 합니다.`
  if (count(/[A-Z]/g) < rules.minUpper) return `대문자를 ${rules.minUpper}개 이상 넣으세요.`
  if (count(/[a-z]/g) < rules.minLower) return `소문자를 ${rules.minLower}개 이상 넣으세요.`
  if (count(/[0-9]/g) < rules.minDigit) return `숫자를 ${rules.minDigit}개 이상 넣으세요.`
  const symbols = rules.symbolSet.split('')
  if (password.split('').filter((char) => symbols.includes(char)).length < rules.minSymbol) {
    return `기호(${rules.symbolSet})를 ${rules.minSymbol}개 이상 넣으세요.`
  }
  return null
}

/** Step 1: prove the current password with a fresh OPAQUE login bound to this session. */
export async function confirmCurrentPassword(email: string, currentPassword: string): Promise<{ outcome: ChangeOutcome; session?: PasswordChangeSession }> {
  const identity = normalizeIdentifier(email)
  try {
    const client = new OpaqueClient(config, ScryptMemHardFn)
    const ke1 = await client.authInit(currentPassword)
    if (ke1 instanceof Error) return { outcome: 'unavailable' }
    const start = await apiFetch<{ ke2: string; credentialIdentifier?: string; serverIdentity: string; transcriptId: string }>('/api/me/password/verify-start', {
      method: 'POST',
      body: JSON.stringify({ ke1: toWire(ke1.serialize()) }),
    })
    // Bind the identity the browser already knows, never one the server supplies.
    if (normalizeIdentifier(start.credentialIdentifier ?? identity) !== identity) return { outcome: 'unavailable' }
    const finished = await client
      .authFinish(KE2.deserialize(config, fromWire(start.ke2)), start.serverIdentity, identity)
      .catch((error: unknown) => (error instanceof Error ? error : new Error('OPAQUE finish failed')))
    if (finished instanceof Error) return { outcome: 'wrong_password' }
    const done = await apiFetch<{ confirmed: boolean; rules: PasswordRules }>('/api/me/password/verify-finish', {
      method: 'POST',
      body: JSON.stringify({ ke3: toWire(finished.ke3.serialize()), transcriptId: start.transcriptId }),
    })
    return done.confirmed ? { outcome: 'ok', session: { rules: done.rules, email: identity } } : { outcome: 'wrong_password' }
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.status === 429) return { outcome: 'rate_limited' }
      if (error.status === 401 || error.status === 403) return { outcome: 'wrong_password' }
    }
    return { outcome: 'unavailable' }
  }
}

/** Step 2: register the new password. The server only ever sees OPAQUE messages. */
export async function registerNewPassword(session: PasswordChangeSession, newPassword: string): Promise<ChangeOutcome> {
  try {
    const client = new OpaqueClient(config, ScryptMemHardFn)
    const request = await client.registerInit(newPassword)
    if (request instanceof Error) return 'unavailable'
    const start = await apiFetch<{ registrationResponse: string; credentialIdentifier: string; serverIdentity: string }>('/api/me/password/register-start', {
      method: 'POST',
      body: JSON.stringify({ registrationRequest: toWire(request.serialize()) }),
    })
    // The account identifier is what the server stores the record under, so it must be the one the sign-in uses.
    // It has to equal the e-mail this page already knows; a different value would lock the person out.
    if (normalizeIdentifier(start.credentialIdentifier) !== session.email) return 'unavailable'
    const finished = await client.registerFinish(RegistrationResponse.deserialize(config, fromWire(start.registrationResponse)), start.serverIdentity, start.credentialIdentifier)
    if (finished instanceof Error) return 'unavailable'
    await apiFetch('/api/me/password/register-finish', { method: 'POST', body: JSON.stringify({ record: toWire(finished.record.serialize()) }) })
    return 'ok'
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.status === 429) return 'rate_limited'
      if (error.status === 403 || error.status === 401 || error.status === 409) return 'expired'
    }
    return 'unavailable'
  }
}
