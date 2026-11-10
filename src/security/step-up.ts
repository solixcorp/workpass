import type { Env } from "../env";

/**
 * Step-up challenge for risky interactive logins (authentik-style: bind the
 * Authenticator Validation stage to run ONLY when the GeoIP/device policy
 * flags the request, and let the session continue after the extra factor).
 *
 * Contract:
 * - `enforce` mode + risk action `step_up` with enrollable second factors:
 *   the session is issued and a challenge row is opened for it; the sign-in /
 *   authorize response carries `stepUpChallenge`, and OAuth authorization
 *   (SSO issuance) is withheld until the challenge is satisfied.
 * - No enrollable factors: fail closed — the session is withheld (unchanged
 *   pre-challenge behavior).
 * - Satisfaction: a session-bound MFA proof (`src/mfa/second-factor.ts` —
 *   TOTP/OTP/backup-code verify, Duo push, hardware OTP) marks all unexpired
 *   pending challenges of that user satisfied. Sessions are rotated on
 *   verification, so the new session carries the proof itself; the gate at
 *   authorization honors a proof on the acting session directly.
 * - Expiry: an open challenge is valid for `STEP_UP_CHALLENGE_TTL_SECONDS`
 *   (default 900). A satisfied requirement continues to authorize the session
 *   for 24 hours, after which a new risky decision challenges again. The cron
 *   removes expired rows.
 *
 * The challenge restricts SSO issuance only (evaluation happens on the
 * identity-boundary paths, per docs/security/device-risk-and-trust.md); a
 * browser session with an open challenge works for its own account surfaces
 * but cannot obtain an authorization result.
 */

export type StepUpChallengeState = "none" | "pending" | "satisfied" | "expired";

export interface StepUpChallenge {
  state: StepUpChallengeState;
  reasons: string[];
  requestPath: string;
  createdAt: string | null;
  expiresAt: string | null;
  satisfiedAt: string | null;
  satisfiedMethod: string | null;
}

export function stepUpChallengeTtlSeconds(env: Env): number {
  const raw = env.STEP_UP_CHALLENGE_TTL_SECONDS;
  if (raw === undefined || raw.trim() === "") return 900;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 300 || value > 3600) {
    throw new Error("STEP_UP_CHALLENGE_TTL_SECONDS must be an integer between 300 and 3600");
  }
  return value;
}

/** How long a satisfied requirement keeps authorizing the session. */
const SATISFIED_RETENTION_MS = 24 * 60 * 60 * 1000;

export function validateStepUpConfig(env: Env): void {
  stepUpChallengeTtlSeconds(env);
}

export async function openStepUpChallenge(input: {
  env: Env;
  sessionToken: string;
  userId: string;
  reasons: string[];
  requestPath: string;
}): Promise<boolean> {
  const ttl = stepUpChallengeTtlSeconds(input.env);
  const now = Date.now();
  const createdAt = new Date(now).toISOString();
  const expiresAt = new Date(now + ttl * 1000).toISOString();
  const reasonsJson = JSON.stringify(input.reasons.slice(0, 5));
  const result = await input.env.DB.prepare(
    `INSERT INTO session_step_up_requirements
      (session_token, user_id, reasons, request_path, created_at, challenge_expires_at, satisfied_at, satisfied_method)
     VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
     ON CONFLICT(session_token) DO UPDATE SET
       reasons = excluded.reasons,
       request_path = excluded.request_path,
       created_at = excluded.created_at,
       challenge_expires_at = excluded.challenge_expires_at,
       satisfied_at = NULL,
       satisfied_method = NULL`,
  )
    .bind(input.sessionToken, input.userId, reasonsJson, input.requestPath, createdAt, expiresAt)
    .run();
  return result.meta.changes >= 1;
}

async function readChallengeRow(
  env: Env,
  sessionToken: string,
): Promise<{
  reasons: string;
  request_path: string;
  created_at: string;
  challenge_expires_at: string;
  satisfied_at: string | null;
  satisfied_method: string | null;
} | null> {
  return env.DB.prepare(
    `SELECT reasons, request_path, created_at, challenge_expires_at, satisfied_at, satisfied_method
     FROM session_step_up_requirements WHERE session_token = ? LIMIT 1`,
  )
    .bind(sessionToken)
    .first();
}

/** Current challenge state for a session token (no DB errors surfaced). */
export async function getStepUpChallenge(env: Env, sessionToken: string): Promise<StepUpChallenge> {
  const none: StepUpChallenge = {
    state: "none",
    reasons: [],
    requestPath: "",
    createdAt: null,
    expiresAt: null,
    satisfiedAt: null,
    satisfiedMethod: null,
  };
  if (!sessionToken || sessionToken.length > 512) return none;
  try {
    const row = await readChallengeRow(env, sessionToken);
    if (!row) return none;
    let reasons: string[] = [];
    try {
      const parsed: unknown = JSON.parse(row.reasons);
      if (Array.isArray(parsed)) reasons = parsed.filter((r): r is string => typeof r === "string");
    } catch {
      reasons = [];
    }
    if (row.satisfied_at !== null) {
      return {
        state: "satisfied",
        reasons,
        requestPath: row.request_path,
        createdAt: row.created_at,
        expiresAt: row.challenge_expires_at,
        satisfiedAt: row.satisfied_at,
        satisfiedMethod: row.satisfied_method,
      };
    }
    const expired = Date.parse(row.challenge_expires_at) <= Date.now();
    return {
      state: expired ? "expired" : "pending",
      reasons,
      requestPath: row.request_path,
      createdAt: row.created_at,
      expiresAt: row.challenge_expires_at,
      satisfiedAt: null,
      satisfiedMethod: null,
    };
  } catch {
    // Fail closed: an unreadable challenge state must not authorize issuance.
    return { ...none, state: "expired" };
  }
}

/**
 * Mark every unexpired pending challenge of the user satisfied. Called after a
 * durable session-bound MFA proof is recorded; challenge rows may reference
 * rotated-away sessions, so satisfying is user-scoped on purpose.
 */
export async function satisfyPendingStepUpChallenges(env: Env, userId: string): Promise<number> {
  if (!userId) return 0;
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    `UPDATE session_step_up_requirements
     SET satisfied_at = ?, satisfied_method = 'mfa_proof'
     WHERE user_id = ? AND satisfied_at IS NULL AND challenge_expires_at > ?`,
  )
    .bind(now, userId, now)
    .run();
  return result.meta.changes;
}

/**
 * Remove open challenges whose window has passed and satisfied rows past the
 * 24-hour authorization retention; wired into the daily cron.
 */
export async function cleanupStepUpChallenges(env: Env, now: Date): Promise<void> {
  const expiredBefore = new Date(now.getTime()).toISOString();
  const staleSatisfied = new Date(now.getTime() - SATISFIED_RETENTION_MS).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM session_step_up_requirements WHERE satisfied_at IS NULL AND challenge_expires_at <= ?")
      .bind(expiredBefore),
    env.DB.prepare("DELETE FROM session_step_up_requirements WHERE satisfied_at IS NOT NULL AND satisfied_at < ?")
      .bind(staleSatisfied),
  ]);
}

/** Which second-factor methods this account can actually complete. */
export async function usableSecondFactors(env: Env, userId: string): Promise<string[]> {
  const { mfaPolicy } = await import("../mfa/policy");
  const policy = mfaPolicy(env);
  const methods: string[] = [];
  try {
    const user = await env.DB.prepare(
      `SELECT "twoFactorEnabled" AS twoFactorEnabled FROM "user" WHERE id = ? LIMIT 1`,
    )
      .bind(userId)
      .first<{ twoFactorEnabled: number | boolean | null }>();
    if (user?.twoFactorEnabled === 1 || user?.twoFactorEnabled === true) {
      const secret = await env.DB.prepare(
        `SELECT verified FROM "twoFactor" WHERE userId = ? LIMIT 1`,
      ).bind(userId).first<{ verified: number | boolean | null }>().catch(() => null);
      // An authenticator secret exists only after TOTP enrollment; OTP-only
      // accounts have none. Backup codes ride on the same row.
      const hasSecret = secret !== null && secret.verified !== 0 && secret.verified !== false;
      if (hasSecret && policy.allow.totp) methods.push("totp");
      if (policy.allow.otp) methods.push("otp");
      if (hasSecret) methods.push("backup_code");
    }
  } catch {
    // Treat as unknown below; fall through to platform-managed factors.
  }
  try {
    const { userHasHotpToken } = await import("../mfa/hotp");
    if (policy.allow.hotp && await userHasHotpToken(env, userId)) methods.push("hotp");
  } catch {
    // Unreadable hardware token state stays silent; availability is best-effort.
  }
  try {
    const { duoConfig } = await import("../mfa/duo");
    if (policy.allow.duo && duoConfig(env)) methods.push("duo_push");
  } catch {
    // Duo presence check is best-effort.
  }
  return methods;
}
