import Fingerprint from '@fingerprint/agent'
import { queryOptions } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

export type LoginConfig = {
  app: { id: string; name: string; signInTitle: string; icon: string | null }
  organization: { name: string }
  login: { passkey: boolean }
  fingerprint: { publicKey: string; region: 'us' | 'eu' | 'ap'; endpoint: string | null } | null
}

export const loginConfigQuery = queryOptions({
  queryKey: ['login-config'],
  queryFn: () => apiFetch<LoginConfig>('/api/config/login'),
  staleTime: Infinity,
})

// The agent needs about a second after start() to collect its signals.
const WARM_UP_MS = 1100
const GET_TIMEOUT_MS = 8000

type Agent = ReturnType<typeof Fingerprint.start>

let started: { agent: Agent; readyAt: number } | null = null

/** Start collecting as early as possible; safe to call repeatedly. */
export function startFingerprint(config: LoginConfig['fingerprint']): void {
  if (!config || started) return
  try {
    started = {
      agent: Fingerprint.start({
        apiKey: config.publicKey,
        region: config.region,
        // The workspace's own subdomain: identification requests stay first-party.
        ...(config.endpoint ? { endpoints: [config.endpoint] } : {}),
      }),
      readyAt: Date.now() + WARM_UP_MS,
    }
  } catch {
    started = null
  }
}

/**
 * One identification event id for a sensitive action. Event ids are single use
 * on the server, so call this once per login request. Returns null when the
 * agent is off or fails; the backend then decides according to its mode.
 */
export async function fingerprintEventId(
  config: LoginConfig['fingerprint'],
  action: string,
  linkedId?: string,
): Promise<string | null> {
  if (!config) return null
  startFingerprint(config)
  if (!started) return null
  const wait = started.readyAt - Date.now()
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait))
  try {
    const result = await started.agent.get({
      timeout: GET_TIMEOUT_MS,
      tags: { action },
      ...(linkedId ? { linkedId } : {}),
    })
    return result.event_id
  } catch {
    return null
  }
}
