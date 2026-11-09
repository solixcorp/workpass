/**
 * The oauthProvider extension that contributes released claims to access
 * tokens, ID tokens, and the UserInfo response. The provider passes the
 * session id (`sid`) for session-backed grants; the release helpers fail
 * closed on the operator flags, so this extension is registered always.
 */

import type { OAuthProviderExtension } from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { oidcClaimRelease } from "./protocol-claims";

export function claimReleaseExtension(env: Env): OAuthProviderExtension {
  return {
    claims: {
      accessToken: async ({ sessionId, user }) => await oidcClaimRelease(env, sessionId, user?.id),
      idToken: async ({ sessionId, user }) => await oidcClaimRelease(env, sessionId, user?.id),
      userInfo: async ({ user }) => await oidcClaimRelease(env, null, user?.id),
    },
  };
}
