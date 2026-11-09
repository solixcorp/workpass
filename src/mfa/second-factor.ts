/**
 * Session-bound MFA proofs for requireMfa application policies.
 *
 * Enrollment (a configured TOTP, an enrolled hardware token, twoFactorEnabled)
 * is NOT evidence that a session passed a second factor. A proof row binds a
 * successful second-factor verification to the exact session token that
 * performed it; the SSO issuance points require that row before satisfying a
 * policy. Trust-device cookies bypass the Better Auth challenge on later
 * sign-ins and therefore do NOT produce a proof; such sessions must step up
 * through one of the verification endpoints first.
 *
 * Recording points (all fail closed on write failure):
 * - Better Auth /two-factor/verify-totp, /verify-otp, /verify-backup-code
 *   (intercepted in src/audit/auth-middleware.ts; the response carries the
 *   session token for both the sign-in and already-signed-in cases).
 * - /api/mfa/hotp/verify and /api/mfa/duo/verify (result "allow") in
 *   src/mfa/duo-routes.ts — step-up verification inside a live session.
 */

import type { Env } from "../env";
import { userHasHotpToken } from "./hotp";

/** Minimal structural view of a Better Auth getSession result. */
export interface MfaCheckedSession {
  user: { id: string };
  session?: { token?: unknown } | null;
}

const PROOF_TOKEN_MAX_LENGTH = 512;

function proofSessionToken(session: MfaCheckedSession): string | null {
  const token = session.session?.token;
  return typeof token === "string" && token.length > 0 && token.length <= PROOF_TOKEN_MAX_LENGTH
    ? token
    : null;
}

/** Record a proof: THIS session token belongs to THIS user and verified a second factor. */
export async function recordSessionMfaProof(env: Env, sessionToken: string, userId: string): Promise<boolean> {
  if (!sessionToken || sessionToken.length > PROOF_TOKEN_MAX_LENGTH || !userId) return false;
  try {
    await env.DB.prepare(
      `INSERT INTO session_mfa_proofs (session_token, user_id, verified_at)
       VALUES (?, ?, ?)
       ON CONFLICT (session_token) DO UPDATE SET
         user_id = excluded.user_id,
         verified_at = excluded.verified_at`,
    ).bind(sessionToken, userId, new Date().toISOString()).run();
    return true;
  } catch {
    return false;
  }
}

/** The recorded proof for a session token, if any. */
export async function getSessionMfaProof(
  env: Env,
  sessionToken: string,
): Promise<{ userId: string; verifiedAt: string } | null> {
  if (!sessionToken || sessionToken.length > PROOF_TOKEN_MAX_LENGTH) return null;
  const row = await env.DB.prepare(
    "SELECT user_id AS userId, verified_at AS verifiedAt FROM session_mfa_proofs WHERE session_token = ?",
  ).bind(sessionToken).first<{ userId: string; verifiedAt: string }>().catch(() => null);
  if (!row) return null;
  return { userId: row.userId, verifiedAt: row.verifiedAt };
}

/**
 * The requireMfa gate shared by every SSO issuance point: the ACTING session
 * must carry its own verification proof. This deliberately checks the proof
 * rows, not enrollment flags, and denies stale or mismatched records.
 */
export async function sessionSatisfiesRequireMfa(env: Env, session: MfaCheckedSession): Promise<boolean> {
  const sessionToken = proofSessionToken(session);
  if (!sessionToken) return false;
  const proof = await getSessionMfaProof(env, sessionToken);
  return proof !== null && proof.userId === session.user.id;
}

/** Remove proofs whose backing session can no longer be active. */
export async function cleanupSessionMfaProofs(env: Env, now = new Date()): Promise<void> {
  const table = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'session_mfa_proofs'",
  ).first<{ name: string }>();
  if (!table) return;
  await env.DB.prepare("DELETE FROM session_mfa_proofs WHERE verified_at < ?")
    .bind(new Date(now.getTime() - 31 * 24 * 60 * 60 * 1000).toISOString())
    .run();
}

/**
 * Status endpoint support (display only, never a gate): does the user have a
 * second factor enrolled?
 */
export async function userHasSecondFactorEnrolled(env: Env, userId: string): Promise<boolean> {
  return await userHasHotpToken(env, userId);
}
