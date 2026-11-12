/**
 * Second-factor policy: which methods the administrator allows, who must use
 * a second factor, and the passkey switch. Values come from admin settings
 * (overlaid on the environment by src/settings/store.ts), so everything here
 * reads plain env fields.
 */

import type { Env } from "../env";
import { loadAppAccessPolicy } from "../access/policies";
import { workpassClientId } from "../auth/workpass";

export type MfaMethod = "totp" | "otp" | "hotp" | "duo";
export type MfaRequirement = "off" | "admins" | "everyone";

export interface MfaPolicy {
  require: MfaRequirement;
  allow: Record<MfaMethod, boolean>;
}

const on = (value: string | undefined) => value !== "off";

export function mfaPolicy(env: Env): MfaPolicy {
  const require = env.MFA_REQUIRE === "admins" || env.MFA_REQUIRE === "everyone" ? env.MFA_REQUIRE : "off";
  return {
    require,
    allow: {
      totp: on(env.MFA_ALLOW_TOTP),
      otp: on(env.MFA_ALLOW_OTP),
      hotp: on(env.MFA_ALLOW_HOTP),
      duo: on(env.MFA_ALLOW_DUO),
    },
  };
}

export function passkeyAllowed(env: Env): boolean {
  return on(env.LOGIN_ALLOW_PASSKEY);
}

function isAdminRole(role: unknown): boolean {
  return typeof role === "string" && role.split(",").includes("admin");
}

/** Must this account use a second factor under the current policy? */
export function userMustUseMfa(env: Env, user: { role?: unknown }): boolean {
  const { require } = mfaPolicy(env);
  if (require === "everyone") return true;
  return require === "admins" && isAdminRole(user.role);
}

export async function userMustUseMfaById(env: Env, userId: string): Promise<boolean> {
  const row = await env.DB.prepare('SELECT role FROM "user" WHERE id = ? LIMIT 1')
    .bind(userId).first<{ role: string | null }>().catch(() => null);
  return row ? userMustUseMfa(env, row) : false;
}

const TOTP_PATHS = new Set([
  "/api/auth/two-factor/get-totp-uri",
  "/api/auth/two-factor/verify-totp",
]);

/**
 * Policy gate in front of the Better Auth two-factor and passkey endpoints.
 * Returns a rejection response, or null to continue. Method switches and the
 * "cannot turn it off while required" rule live here so the browser cannot
 * route around the screens the server defines.
 */
export async function enforceMfaPolicy(
  request: Request,
  env: Env,
  session: { user: { id: string; role?: unknown }; session?: { token?: unknown } | null } | null,
): Promise<Response | null> {
  if (request.method !== "POST") return null;
  const path = new URL(request.url).pathname;
  const policy = mfaPolicy(env);
  const deny = (message: string) => Response.json({ error: message }, { status: 403 });

  if (path.startsWith("/api/auth/passkey/") && !passkeyAllowed(env)) {
    return deny("패스키는 사용할 수 없습니다.");
  }
  if (TOTP_PATHS.has(path) && !policy.allow.totp) return deny("인증 앱은 사용할 수 없습니다.");
  if ((path === "/api/auth/two-factor/verify-otp" || path === "/api/auth/two-factor/send-otp") && !policy.allow.otp) {
    return deny("일회용 코드는 사용할 수 없습니다.");
  }
  if (path === "/api/auth/two-factor/enable") {
    if (session && !(await (await import("./second-factor")).mayEnrollFactor(env, session))) {
      return deny("Additional verification is required before adding a factor.");
    }
    let method = "totp";
    try {
      const body = await request.clone().json() as { method?: unknown };
      if (body?.method === "otp") method = "otp";
    } catch {
      // Default method applies.
    }
    if (method === "totp" && !policy.allow.totp) return deny("인증 앱은 사용할 수 없습니다.");
    if (method === "otp") return deny("Use OTP enrollment verification to enable one-time codes.");
  }
  if (path === "/api/auth/two-factor/disable" && session && userMustUseMfa(env, session.user)) {
    return deny("2차 인증이 필수라서 끌 수 없습니다.");
  }
  return null;
}

/**
 * Must this user pass a second factor to sign in to WorkPass itself? True for
 * the global requirement or when the WorkPass app policy asks for MFA. Users
 * with no factor yet are not blocked here: they need a session to enroll.
 */
export async function workpassMfaRequired(env: Env, user: { role?: unknown }): Promise<boolean> {
  if (userMustUseMfa(env, user)) return true;
  const policy = await loadAppAccessPolicy(env, `oidc:${await workpassClientId(env)}`).catch(() => null);
  return policy?.requireMfa === true;
}

/** A required second factor the account can already complete: ask for it at sign-in. */
export async function loginRequiresSecondFactor(env: Env, userId: string): Promise<boolean> {
  const row = await env.DB.prepare('SELECT role FROM "user" WHERE id = ? LIMIT 1')
    .bind(userId).first<{ role: string | null }>().catch(() => null);
  if (!row || !(await workpassMfaRequired(env, row))) return false;
  const { usableSecondFactors } = await import("../security/step-up");
  return (await usableSecondFactors(env, userId)).length > 0;
}
