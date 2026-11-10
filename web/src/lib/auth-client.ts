import { passkeyClient } from '@better-auth/passkey/client'
import { adminClient, twoFactorClient, usernameClient } from 'better-auth/client/plugins'
import { createAuthClient } from 'better-auth/react'

// Same-origin client: the SPA is served by the Worker that hosts /api/auth,
// so session cookies stay HttpOnly and never reach JavaScript storage.
export const authClient = createAuthClient({
  baseURL: window.location.origin,
  basePath: '/api/auth',
  plugins: [usernameClient(), passkeyClient(), twoFactorClient(), adminClient()],
})

export type AuthSession = typeof authClient.$Infer.Session

export function isAdministrator(session: AuthSession | null | undefined): boolean {
  const role = (session?.user as { role?: unknown } | undefined)?.role
  return typeof role === 'string' && role.split(',').includes('admin')
}
