/**
 * The oauthProvider extension that contributes released claims to access
 * tokens, ID tokens, and the UserInfo response. The provider passes the
 * session id (`sid`) for session-backed grants; the release helpers fail
 * closed on the operator flags, so this extension is registered always.
 *
 * The requesting client narrows the release through its claim-release policy
 * on `oidc:<clientId>` (an AND with the global flags; no row keeps the
 * flag-only default).
 */

import type { OAuthProviderExtension } from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { oidcClaimRelease, oidcClaimReleaseForSubject, scopeClaimsForSubject } from "./protocol-claims";

function clientSubject(client: { clientId?: unknown } | undefined | null): string | undefined {
  const clientId = client?.clientId;
  return typeof clientId === "string" && clientId.length > 0 ? `oidc:${clientId}` : undefined;
}

/** Subject-aware release for one (session, user) pair; never throws. */
async function releaseFor(
  env: Env,
  sessionId: string | null | undefined,
  user: { id?: string; phoneNumber?: unknown; phoneNumberVerified?: unknown } | null | undefined,
  subject: string | undefined,
  scopes: string[] | undefined,
): Promise<Record<string, unknown>> {
  const userId = user?.id ?? null;
  const base = subject
    ? await oidcClaimReleaseForSubject(env, sessionId, userId, subject).catch(() =>
        // Never retry without the subject: that would bypass its release policy.
        ({}),
      )
    : await oidcClaimRelease(env, sessionId, userId).catch(() => ({}));
  // Scope-gated claims (phone, groups) ride on top of the released base; they
  // never throw (a query failure leaves the claim absent).
  const scoped = await scopeClaimsForSubject(env, userId, subject, scopes, user).catch(() => ({}));
  return { ...base, ...scoped };
}

export function claimReleaseExtension(env: Env): OAuthProviderExtension {
  return {
    claims: {
      accessToken: async ({ sessionId, user, client, scopes }) =>
        await releaseFor(env, sessionId, user, clientSubject(client), scopes),
      idToken: async ({ sessionId, user, client, scopes }) =>
        await releaseFor(env, sessionId, user, clientSubject(client), scopes),
      userInfo: async ({ user, client, scopes }) =>
        await releaseFor(env, null, user, clientSubject(client), scopes),
    },
  };
}
