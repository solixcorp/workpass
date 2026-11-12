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
export async function recordSessionMfaProof(env: Env, sessionToken: string, userId: string, method?: string): Promise<boolean> {
  if (!sessionToken || sessionToken.length > PROOF_TOKEN_MAX_LENGTH || !userId) return false;
  try {
    await env.DB.prepare(
      `INSERT INTO session_mfa_proofs (session_token, user_id, verified_at, methods)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (session_token) DO UPDATE SET
         methods = CASE WHEN session_mfa_proofs.user_id != excluded.user_id THEN excluded.methods
           WHEN instr(',' || session_mfa_proofs.methods || ',', ',' || excluded.methods || ',') > 0 THEN session_mfa_proofs.methods
           ELSE session_mfa_proofs.methods || ',' || excluded.methods END,
         user_id = excluded.user_id,
         verified_at = excluded.verified_at`,
    ).bind(sessionToken, userId, new Date().toISOString(), ["totp", "hotp", "duo", "passkey", "email", "sms"].includes(method ?? "") ? method : "unknown").run();
    // Never satisfy another independent session's challenge.
    try {
      const { satisfyPendingStepUpChallenges } = await import("../security/step-up");
      // A passkey proof answers an app policy, never the separate risk gate.
      if (method !== "passkey") await satisfyPendingStepUpChallenges(env, userId, sessionToken);
    } catch {
      // Record-keeping only; the proof itself remains the durable evidence.
    }
    return true;
  } catch {
    return false;
  }
}

/** The recorded proof for a session token, if any. */
export async function getSessionMfaProof(
  env: Env,
  sessionToken: string,
  strict = false,
): Promise<{ userId: string; verifiedAt: string; methods: string[] } | null> {
  if (!sessionToken || sessionToken.length > PROOF_TOKEN_MAX_LENGTH) return null;
  const row = await env.DB.prepare(
    "SELECT user_id AS userId, verified_at AS verifiedAt, methods FROM session_mfa_proofs WHERE session_token = ?",
  ).bind(sessionToken).first<{ userId: string; verifiedAt: string; methods: string }>().catch((error) => { if (strict) throw error; return null; });
  if (!row) return null;
  return { userId: row.userId, verifiedAt: row.verifiedAt, methods: (row.methods ?? "unknown").split(",") };
}

/**
 * The requireMfa gate shared by every SSO issuance point: the ACTING session
 * must carry its own verification proof. This deliberately checks the proof
 * rows, not enrollment flags, and denies stale or mismatched records.
 */
export async function sessionSatisfiesRequireMfa(env: Env, session: MfaCheckedSession, requiredMethods: string[] = []): Promise<boolean> {
  const sessionToken = proofSessionToken(session);
  if (!sessionToken) return false;
  const proof = await getSessionMfaProof(env, sessionToken);
  return proof !== null && proof.userId === session.user.id &&
    (requiredMethods.length === 0 || requiredMethods.some((method) => proof.methods.includes(method)));
}

/** How long a password or second-factor reverification stays valid for adding a factor. */
export const ENROLL_GATE_TTL_MS = 10 * 60 * 1000;

export interface EnrollGateState {
  passwordOk: boolean;
  secondOk: boolean;
  /** "existing": a factor the account already holds must be verified. "email": none exists, so a one-time code is the minimum. */
  secondMode: "existing" | "email";
}

/**
 * Where the acting session stands on the reverification needed to add a
 * factor: a fresh password proof AND a fresh second verification. Throws on
 * storage failure so callers fail closed.
 */
export async function enrollGateState(env: Env, session: MfaCheckedSession): Promise<EnrollGateState> {
  const token = proofSessionToken(session);
  const userId = session.user.id;
  const none: EnrollGateState = { passwordOk: false, secondOk: false, secondMode: "email" };
  if (!token) return none;
  const fresh = (at: number | null | undefined) => typeof at === "number" && Date.now() - at <= ENROLL_GATE_TTL_MS && at <= Date.now() + 5000;
  const gate = await env.DB.prepare("SELECT user_id AS userId, password_at AS passwordAt, second_at AS secondAt FROM mfa_enroll_gates WHERE session_token = ?")
    .bind(token).first<{ userId: string; passwordAt: number | null; secondAt: number | null }>();
  const ownGate = gate && gate.userId === userId ? gate : null;

  const user = await env.DB.prepare('SELECT "twoFactorEnabled" AS enabled FROM "user" WHERE id = ?')
    .bind(userId).first<{ enabled: number | boolean | null }>();
  if (!user) return none;
  const passkey = await env.DB.prepare('SELECT id FROM "passkey" WHERE "userId" = ? LIMIT 1')
    .bind(userId).first<{ id: string }>();
  const { usableSecondFactors } = await import("../security/step-up");
  const { duoConfig } = await import("./duo");
  const hasExisting = Boolean(user.enabled) || Boolean(passkey) || await userHasHotpToken(env, userId)
    || (await usableSecondFactors(env, userId)).length > 0 || Boolean(duoConfig(env));

  let secondOk = false;
  if (hasExisting) {
    const proof = await getSessionMfaProof(env, token, true);
    secondOk = proof?.userId === userId && fresh(Date.parse(proof.verifiedAt));
  } else {
    secondOk = fresh(ownGate?.secondAt);
  }
  return { passwordOk: fresh(ownGate?.passwordAt), secondOk, secondMode: hasExisting ? "existing" : "email" };
}

/**
 * Adding any second factor needs this session to have just re-proved the
 * account password and a second verification (an existing factor, or a
 * one-time code when the account has none). Checked again at confirmation.
 */
export async function mayEnrollFactor(env: Env, session: MfaCheckedSession): Promise<boolean> {
  try {
    const token = proofSessionToken(session);
    if (!token) return false;
    const { getStepUpChallenge } = await import("../security/step-up");
    const challenge = await getStepUpChallenge(env, token, true);
    if (challenge.state === "pending" || challenge.state === "expired") return false;
    const state = await enrollGateState(env, session);
    return state.passwordOk && state.secondOk;
  } catch {
    return false;
  }
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
