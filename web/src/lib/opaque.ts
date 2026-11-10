import type { StepUpUi } from '@/lib/step-up'
import {
  getOpaqueConfig,
  KE2,
  OpaqueClient,
  OpaqueID,
  ScryptMemHardFn,
} from '@cloudflare/opaque-ts'

// Must match the server suite in src/auth/opaque.ts.
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

export function normalizeIdentifier(identifier: string): string {
  return identifier.trim().toLowerCase()
}

export type StepUpRequirement = {
  required: true
  methods: string[]
  expiresAt: string | null
  ui: StepUpUi
}

export type OpaqueSignInResult =
  | { status: 'ok'; stepUp: StepUpRequirement | null }
  // Wrong password, unknown account and unenrolled account are deliberately
  // one outcome: the server answers all three identically.
  | { status: 'invalid_credentials' }
  | { status: 'rate_limited' }
  | { status: 'denied' }
  | { status: 'unavailable' }

async function postJson(path: string, body: unknown): Promise<Response> {
  return await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
}

/**
 * OPAQUE (RFC 9807) password sign-in. The password is consumed only by the
 * local OPAQUE client; the requests carry KE1/KE3 protocol messages, never the
 * password or anything derived from it. The session arrives as an HttpOnly
 * cookie on the finish response; the response token is ignored on purpose.
 */
export async function opaqueSignIn(
  identifier: string,
  password: string,
  fingerprintEventId?: string | null,
): Promise<OpaqueSignInResult> {
  const username = normalizeIdentifier(identifier)
  const client = new OpaqueClient(config, ScryptMemHardFn)
  const ke1 = await client.authInit(password)
  if (ke1 instanceof Error) return { status: 'unavailable' }

  const startResponse = await postJson('/api/opaque/auth/start', {
    username,
    ke1: toWire(ke1.serialize()),
    ...(fingerprintEventId ? { fingerprint: { event_id: fingerprintEventId } } : {}),
  }).catch(() => null)
  if (!startResponse) return { status: 'unavailable' }
  if (startResponse.status === 429) return { status: 'rate_limited' }
  if (!startResponse.ok) return { status: 'unavailable' }
  const start = (await startResponse.json()) as {
    ke2: string
    serverIdentity: string
    transcriptId: string
  }

  // Bind the identity the user typed, never one supplied by the server.
  const finished = await client
    .authFinish(KE2.deserialize(config, fromWire(start.ke2)), start.serverIdentity, username)
    .catch((error: unknown) => (error instanceof Error ? error : new Error('OPAQUE finish failed')))
  if (finished instanceof Error) return { status: 'invalid_credentials' }

  const finishResponse = await postJson('/api/opaque/auth/finish', {
    username,
    ke3: toWire(finished.ke3.serialize()),
    transcriptId: start.transcriptId,
  }).catch(() => null)
  if (!finishResponse) return { status: 'unavailable' }
  if (finishResponse.status === 401) return { status: 'invalid_credentials' }
  if (finishResponse.status === 429) return { status: 'rate_limited' }
  if (finishResponse.status === 403) return { status: 'denied' }
  if (!finishResponse.ok) return { status: 'unavailable' }

  const body = (await finishResponse.json().catch(() => ({}))) as {
    stepUpChallenge?: StepUpRequirement
  }
  return { status: 'ok', stepUp: body.stepUpChallenge?.required ? body.stepUpChallenge : null }
}
