import type { Env } from "../env";
import { hashPassword } from "../auth/password";
import { digestVisitorId } from "./fingerprint";

/**
 * Admin-issued one-time account recovery tokens — this deployment's
 * equivalent of authentik's "Create recovery link" (there is no email
 * infrastructure; the administrator delivers the token out of band).
 *
 * Security model:
 * - Recovery exists ONLY for locked accounts: issuance requires an active
 *   (unlifted) lockdown row, redemption requires the user to still be under
 *   that same lockdown.
 * - The token is a 256-bit random secret; only its HMAC-SHA256 digest
 *   (keyed by AUTH_SECRET) is stored. Possession of a live token is treated
 *   as identity for the reset, which is why the default validity is 60
 *   minutes and redemption is single-use and rate-limited per IP.
 * - Redemption sets a new credential password, clears the ban, lifts the
 *   lockdown, and revokes sessions and trusted devices again for safety
 *   (they were already revoked at lockdown). Tokens/MFA enrollments stay in
 *   place: recovery alone proves nothing about the devices; the sign-in that
 *   follows re-runs the normal gates (device risk, MFA when enrolled).
 */

export type RecoveryIssueStatus =
  | "issued"
  | "no_active_lockdown"
  | "user_not_found"
  | "insert_conflict";

export interface RecoveryIssuedToken {
  token: string;
  expiresAt: string;
}

export type RedemptionStatus =
  | "recovered"
  | "invalid_or_expired"
  | "already_used"
  | "no_active_lockdown";

export async function issueRecoveryToken(input: {
  env: Env;
  userId: string;
  actorUserId: string;
  /** Validity of the recovery token; clamped to 5 minutes .. 24 hours. */
  ttlMinutes?: number;
}): Promise<
  {
    status: "issued";
    recovery: RecoveryIssuedToken;
    lockdownId: string;
    expiresAt: string;
  } | {
    status: "no_active_lockdown" | "user_not_found" | "insert_conflict";
  }
> {
  const db = input.env.DB;
  const user = await db.prepare('SELECT id, banned FROM "user" WHERE id = ? LIMIT 1')
    .bind(input.userId)
    .first<{ id: string; banned: number | null }>();
  if (!user) return { status: "user_not_found" };
  const lockdown = await db.prepare(
    "SELECT id FROM account_lockdowns WHERE user_id = ? AND lifted_at IS NULL ORDER BY created_at DESC LIMIT 1",
  )
    .bind(input.userId)
    .first<{ id: string }>();
  if (!lockdown) return { status: "no_active_lockdown" };

  const ttlMinutes = Math.max(5, Math.min(1440, input.ttlMinutes ?? 60));
  const now = Date.now();
  const expiresAt = new Date(now + ttlMinutes * 60_000).toISOString();
  const token = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenDigest = await digestVisitorId(input.env, `account-recovery:${token}`);
  const inserted = await db.prepare(
    `INSERT INTO account_recovery_tokens
      (id, user_id, token_digest, lockdown_id, created_by, created_at, expires_at, used_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
  )
    .bind(crypto.randomUUID(), input.userId, tokenDigest, lockdown.id, input.actorUserId, new Date(now).toISOString(), expiresAt)
    .run();
  if (inserted.meta.changes !== 1) {
    // A 256-bit secret cannot realistically collide; surface the write failure
    // as a distinct conflict the operator can retry.
    return { status: "insert_conflict" };
  }
  return { status: "issued", recovery: { token, expiresAt }, lockdownId: lockdown.id, expiresAt };
}

export async function redeemRecoveryToken(input: {
  env: Env;
  token: string;
  newPassword: string;
}): Promise<
  { status: Extract<RedemptionStatus, "recovered">; userId: string; passwordReset: true } |
  { status: Exclude<RedemptionStatus, "recovered"> }
> {
  const token = input.token;
  if (typeof token !== "string" || token.length < 40 || token.length > 128 || !/^[A-Za-z0-9_-]+$/.test(token)) {
    return { status: "invalid_or_expired" };
  }
  const db = input.env.DB;
  const tokenDigest = await digestVisitorId(input.env, `account-recovery:${token}`);
  const row = await db.prepare(
    `SELECT id, user_id, lockdown_id, expires_at FROM account_recovery_tokens
     WHERE token_digest = ? AND used_at IS NULL AND expires_at > ? LIMIT 1`,
  )
    .bind(tokenDigest, new Date().toISOString())
    .first<{ id: string; user_id: string; lockdown_id: string; expires_at: string }>();
  if (!row) return { status: "invalid_or_expired" };

  // The lockdown must still be active for redemption to apply.
  const lockdown = await db.prepare(
    "SELECT id FROM account_lockdowns WHERE id = ? AND user_id = ? AND lifted_at IS NULL LIMIT 1",
  )
    .bind(row.lockdown_id, row.user_id)
    .first<{ id: string }>();
  if (!lockdown) return { status: "no_active_lockdown" };

  const now = new Date().toISOString();
  const consumed = await db.prepare(
    "UPDATE account_recovery_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL",
  )
    .bind(now, row.id)
    .run();
  if (consumed.meta.changes !== 1) return { status: "already_used" };

  const newHash = await hashPassword(input.newPassword);
  await db.batch([
    db.prepare(
      `UPDATE "user" SET banned = 0, "banReason" = NULL, "banExpires" = NULL, "updatedAt" = ? WHERE id = ?`,
    ).bind(now, row.user_id),
    db.prepare(
      `UPDATE account SET password = ? WHERE "userId" = ? AND providerId = 'credential'`,
    ).bind(newHash, row.user_id),
    db.prepare(
      "UPDATE account_lockdowns SET lifted_at = ?, lifted_by = 'recovery_link' WHERE id = ? AND lifted_at IS NULL",
    ).bind(now, row.lockdown_id),
    // Safety re-revocation: already performed at lockdown, kept idempotent here
    // so the account is guaranteed to start from zero surface after recovery.
    db.prepare('DELETE FROM "session" WHERE "userId" = ?').bind(row.user_id),
    db.prepare(
      "UPDATE trusted_devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
    ).bind(now, row.user_id),
  ]);
  return { status: "recovered", userId: row.user_id, passwordReset: true };
}

/** Remove consumed and expired tokens past a 7-day reconciliation window. */
export async function cleanupRecoveryTokens(env: Env, now: Date): Promise<void> {
  const before = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM account_recovery_tokens WHERE used_at IS NOT NULL AND used_at < ?").bind(before),
    env.DB.prepare("DELETE FROM account_recovery_tokens WHERE used_at IS NULL AND expires_at < ?").bind(before),
  ]);
}

function toBase64Url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
