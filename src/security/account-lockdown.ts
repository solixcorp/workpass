import type { Env } from "../env";
import { hashPassword } from "../auth/password";

/**
 * Account Lockdown (modeled after authentik's account lockdown feature,
 * <https://docs.goauthentik.io/security/account-lockdown/>, adapted to this
 * stack). See docs/security/account-lockdown.md.
 *
 * One call performs:
 * - bans the user (Better Auth sign-in gating + `banned` column); the
 *   installed D1 triggers revoke OAuth access/refresh tokens in the same
 *   statement,
 * - deletes all Better Auth sessions (immediate sign-out everywhere),
 * - sets an unusable password for the credential account,
 * - removes the OPAQUE credential record (the password-less login equivalent),
 * - revokes every trusted device,
 * - records the lockdown with its reason in `account_lockdowns`.
 *
 * Passkeys and TOTP/HOTP enrollments are deliberately kept: re-verifying them
 * during recovery is evidence the original owner is back, matching authentik's
 * guidance to re-enroll rather than silently wipe factors.
 *
 * Recovery is an administrator action (`liftAccountLockdown`): the ban clears
 * and sessions/tokens stay revoked. The password remains unusable until the
 * administrator sets a new one (Better Auth `/api/auth/admin/set-user-password`
 * or the unlock endpoint with `new_password`).
 */

export type LockdownSource = "admin" | "self_service";

export interface LockdownResult {
  status: "performed" | "already_locked" | "user_not_found";
  lockdownId: string | null;
  revokedSessions: number;
  disabledCredentialPassword: number;
  removedOpaqueCredentials: number;
  revokedTrustedDevices: number;
}

export interface LockdownLiftResult {
  status: "lifted" | "no_active_lockdown" | "user_not_found";
  liftedAt: string | null;
  passwordReset: boolean;
}

export async function performAccountLockdown(input: {
  env: Env;
  userId: string;
  /** Acting administrator, or the user themselves for self-service. */
  actorUserId: string;
  source: LockdownSource;
  reason: string;
}): Promise<LockdownResult> {
  const db = input.env.DB;
  const now = new Date().toISOString();
  const user = await db
    .prepare('SELECT id FROM "user" WHERE id = ? LIMIT 1')
    .bind(input.userId)
    .first<{ id: string }>();
  if (!user) {
    return emptyResult("user_not_found");
  }

  // Unusable password: a random secret nobody holds, hashed like any other
  // password so verification always fails without special-casing the login.
  const unusableSecret = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const unusableHash = await hashPassword(unusableSecret);
  const lockdownId = crypto.randomUUID();
  const bannedGuard = "EXISTS (SELECT 1 FROM \"user\" WHERE id = ? AND COALESCE(banned, 0) = 1)";

  const statement = (sql: string, ...params: unknown[]) => db.prepare(sql).bind(...params);
  // One atomic batch: the ban update gates the destructive side effects, so a
  // concurrent ban can never leave the account half-locked-down.
  const results = await db.batch([
    statement(
      `UPDATE "user" SET banned = 1, "banReason" = ?, "banExpires" = NULL, "updatedAt" = ?
       WHERE id = ? AND COALESCE(banned, 0) = 0`,
      input.reason,
      now,
      input.userId,
    ),
    statement(
      `DELETE FROM "session" WHERE "userId" = ? AND ${bannedGuard}`,
      input.userId,
      input.userId,
    ),
    statement(
      `UPDATE account SET password = ? WHERE "userId" = ? AND providerId = 'credential'
       AND ${bannedGuard}`,
      unusableHash,
      input.userId,
      input.userId,
    ),
    statement(
      `DELETE FROM opaque_credential_records WHERE user_id = ? AND ${bannedGuard}`,
      input.userId,
      input.userId,
    ),
    statement(
      `UPDATE trusted_devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND ${bannedGuard}`,
      now,
      input.userId,
      input.userId,
    ),
    statement(
      `INSERT INTO account_lockdowns (id, user_id, actor_user_id, source, reason, created_at, lifted_at, lifted_by)
       SELECT ?, ?, ?, ?, ?, ?, NULL, NULL
       WHERE (SELECT COALESCE(banned, 0) FROM "user" WHERE id = ?) = 1
         AND NOT EXISTS (SELECT 1 FROM account_lockdowns WHERE user_id = ? AND lifted_at IS NULL)`,
      lockdownId,
      input.userId,
      input.actorUserId,
      input.source,
      input.reason,
      now,
      input.userId,
      input.userId,
    ),
  ]);

  const banApplied = (results[0]?.meta.changes ?? 0) >= 1;
  // NOTE: >= 1, not === 1 — the ban statement fires the offboarding triggers
  // that revoke OAuth tokens, and some SQLite runtimes aggregate the
  // trigger-modified rows into the statement's change count.
  if (!banApplied) {
    // Already banned through another path (admin ban-user, SCIM deactivate,
    // a prior lockdown); the account state is the expected one either way.
    return emptyResult("already_locked");
  }
  const lockdownRow = (results[5]?.meta.changes ?? 0) === 1 ? lockdownId : null;
  return {
    status: lockdownRow ? "performed" : "already_locked",
    lockdownId: lockdownRow,
    revokedSessions: results[1]?.meta.changes ?? 0,
    disabledCredentialPassword: results[2]?.meta.changes ?? 0,
    removedOpaqueCredentials: results[3]?.meta.changes ?? 0,
    revokedTrustedDevices: results[4]?.meta.changes ?? 0,
  };
}

export async function liftAccountLockdown(input: {
  env: Env;
  userId: string;
  actorUserId: string;
  newHashedPassword?: string | null;
}): Promise<LockdownLiftResult> {
  const db = input.env.DB;
  const user = await db
    .prepare('SELECT id FROM "user" WHERE id = ? LIMIT 1')
    .bind(input.userId)
    .first<{ id: string }>();
  if (!user) return { status: "user_not_found", liftedAt: null, passwordReset: false };

  const active = await db
    .prepare(
      "SELECT id FROM account_lockdowns WHERE user_id = ? AND lifted_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .bind(input.userId)
    .first<{ id: string }>();
  if (!active) {
    return { status: "no_active_lockdown", liftedAt: null, passwordReset: false };
  }

  const now = new Date().toISOString();
  const passwordReset = input.newHashedPassword !== undefined && input.newHashedPassword !== null;
  const statement = (sql: string, ...params: unknown[]) => db.prepare(sql).bind(...params);
  const results = await db.batch([
    statement(
      `UPDATE "user" SET banned = 0, "banReason" = NULL, "banExpires" = NULL, "updatedAt" = ? WHERE id = ?`,
      now,
      input.userId,
    ),
    ...(passwordReset
      ? [
          statement(
            `UPDATE account SET password = ? WHERE "userId" = ? AND providerId = 'credential'`,
            input.newHashedPassword,
            input.userId,
          ),
        ]
      : []),
    statement(
      "UPDATE account_lockdowns SET lifted_at = ?, lifted_by = ? WHERE id = ? AND lifted_at IS NULL",
      now,
      input.actorUserId,
      active.id,
    ),
  ]);
  const lifted = (results[results.length - 1]?.meta.changes ?? 0) === 1;
  return {
    status: lifted ? "lifted" : "no_active_lockdown",
    liftedAt: lifted ? now : null,
    passwordReset,
  };
}

export async function latestAccountLockdowns(
  env: Env,
  userId: string,
  limit = 10,
): Promise<Array<{
  id: string;
  source: LockdownSource;
  reason: string;
  actorUserId: string;
  createdAt: string;
  liftedAt: string | null;
  liftedBy: string | null;
}>> {
  const rows = await env.DB.prepare(
    `SELECT id, source, reason, actor_user_id, created_at, lifted_at, lifted_by
     FROM account_lockdowns WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
  )
    .bind(userId, Math.max(1, Math.min(50, limit)))
    .all<{
      id: string;
      source: LockdownSource;
      reason: string;
      actor_user_id: string;
      created_at: string;
      lifted_at: string | null;
      lifted_by: string | null;
    }>();
  return rows.results.map((row) => ({
    id: row.id,
    source: row.source,
    reason: row.reason,
    actorUserId: row.actor_user_id,
    createdAt: row.created_at,
    liftedAt: row.lifted_at,
    liftedBy: row.lifted_by,
  }));
}

function emptyResult(status: LockdownResult["status"]): LockdownResult {
  return {
    status,
    lockdownId: null,
    revokedSessions: 0,
    disabledCredentialPassword: 0,
    removedOpaqueCredentials: 0,
    revokedTrustedDevices: 0,
  };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
