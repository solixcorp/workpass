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
import { oidcClaimRelease, oidcClaimReleaseForSubject } from "./protocol-claims";

function clientSubject(client: { clientId?: unknown } | undefined | null): string | undefined {
  const clientId = client?.clientId;
  return typeof clientId === "string" && clientId.length > 0 ? `oidc:${clientId}` : undefined;
}

/** Subject-aware release for one (session, user) pair; never throws. */
async function releaseFor(env: Env, sessionId: string | null | undefined, userId: string | null | undefined, subject: string | undefined): Promise<Record<string, unknown>> {
  if (!subject) return await oidcClaimRelease(env, sessionId, userId);
  try {
    return await oidcClaimReleaseForSubject(env, sessionId, userId, subject);
  } catch {
    // A policy evaluation failure must not become an availability failure:
    // the flag-only default still applies.
    return await oidcClaimRelease(env, sessionId, userId);
  }
}

export function claimReleaseExtension(env: Env): OAuthProviderExtension {
  return {
    claims: {
      accessToken: async ({ sessionId, user, client }) =>
        await releaseFor(env, sessionId, user?.id, clientSubject(client)),
      idToken: async ({ sessionId, user, client }) =>
        await releaseFor(env, sessionId, user?.id, clientSubject(client)),
      userInfo: async ({ user, client }) =>
        await releaseFor(env, null, user?.id, clientSubject(client)),
    },
  };
}
