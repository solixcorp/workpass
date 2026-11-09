/**
 * The second-factor satisfaction check shared by the SSO routes: the user's
 * Better Auth 2FA enrollment (TOTP/OTP) or an enrolled hardware OTP token
 * satisfies a requireMfa application policy. Duo Push is verified per-flow
 * and does not persist.
 */

import { userHasHotpToken } from "./hotp";
import type { Env } from "../env";

export async function userSatisfiesRequireMfa(env: Env, userId: string, twoFactorEnabled: boolean): Promise<boolean> {
  if (twoFactorEnabled) return true;
  return userHasHotpToken(env, userId);
}
