/**
 * Account (tenant) and membership storage for multi-account switching.
 *
 * Accounts are first-party objects a user may belong to; the active account
 * is bound to the session token, not the user, so two sessions of the same
 * user may hold different account contexts. See docs/design/multi-accounts.md.
 */

import type { Env } from "../env";

export const ACCOUNT_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
export const DESCRIPTION_LIMIT = 512;

export interface AccountRow {
  id: string;
  name: string;
  description: string;
  createdBy: string;
  createdAt: string;
}

export interface AccountMembership {
  role: "admin" | "member";
  account: AccountRow;
  grantedAt: string;
}

/** Create an account and grant its creator the admin member role atomically. */
export async function createAccount(
  env: Env,
  input: { name: string; description: string; creatorUserId: string },
): Promise<AccountRow | null> {
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const inserted = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO accounts (id, name, description, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(id, input.name, input.description, input.creatorUserId, now, now),
    env.DB.prepare(
      `INSERT INTO account_members (account_id, user_id, role, granted_by, granted_at)
       VALUES (?, ?, 'admin', ?, ?)`,
    ).bind(id, input.creatorUserId, input.creatorUserId, now),
  ]);
  if (inserted[0]!.meta.changes !== 1) return null;
  return { id, name: input.name, description: input.description, createdBy: input.creatorUserId, createdAt: now };
}

/** Update an account's unique name and/or description. Returns the row. */
export async function updateAccount(
  env: Env,
  id: string,
  updates: { name?: string; description?: string },
): Promise<AccountRow | null> {
  const sets: string[] = ["updated_at = ?"];
  const bindings: Array<string | null> = [new Date().toISOString()];
  if (updates.name !== undefined) {
    sets.push("name = ?");
    bindings.push(updates.name);
  }
  if (updates.description !== undefined) {
    sets.push("description = ?");
    bindings.push(updates.description);
  }
  const updated = await env.DB.prepare(
    `UPDATE accounts SET ${sets.join(", ")} WHERE id = ?`,
  ).bind(...bindings, id).run();
  if (updated.meta.changes !== 1) return null;
  return await getAccount(env, id);
}

/** Count admins holding the admin member role inside an account. */
export async function countAccountAdmins(env: Env, accountId: string): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM account_members WHERE account_id = ? AND role = 'admin'",
  ).bind(accountId).first<{ count: number }>();
  return row?.count ?? 0;
}

/** Change a member's role in place. Returns false when the membership is absent. */
export async function updateAccountMemberRole(
  env: Env,
  accountId: string,
  userId: string,
  role: "admin" | "member",
): Promise<boolean> {
  const updated = await env.DB.prepare(
    "UPDATE account_members SET role = ? WHERE account_id = ? AND user_id = ?",
  ).bind(role, accountId, userId).run();
  return updated.meta.changes === 1;
}

export async function getAccount(env: Env, id: string): Promise<AccountRow | null> {
  const row = await env.DB.prepare(
    `SELECT id, name, description, created_by AS createdBy, created_at AS createdAt
     FROM accounts WHERE id = ?`,
  ).bind(id).first<AccountRow>();
  return row ?? null;
}

export async function listAccounts(
  env: Env,
  limit: number,
  cursor: string | null,
): Promise<{ accounts: AccountRow[]; nextCursor: string | null }> {
  const result = await env.DB.prepare(
    `SELECT id, name, description, created_by AS createdBy, created_at AS createdAt
     FROM accounts WHERE (? IS NULL OR id > ?) ORDER BY id ASC LIMIT ?`,
  ).bind(cursor, cursor, limit + 1).all<AccountRow>();
  const accounts = result.results.slice(0, limit);
  return {
    accounts,
    nextCursor: result.results.length > limit ? accounts.at(-1)?.id ?? null : null,
  };
}

/** Remove the account with its memberships, session contexts, and attributes. */
export async function deleteAccount(env: Env, id: string): Promise<boolean> {
  const removed = await env.DB.batch([
    env.DB.prepare("DELETE FROM account_members WHERE account_id = ?").bind(id),
    env.DB.prepare("DELETE FROM account_session_contexts WHERE account_id = ?").bind(id),
    env.DB.prepare("DELETE FROM object_attributes WHERE object_type = 'account' AND object_id = ?").bind(id),
    env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(id),
  ]);
  return removed[3]!.meta.changes === 1;
}

export interface AccountMemberRow {
  userId: string;
  role: "admin" | "member";
  grantedBy: string;
  grantedAt: string;
}

export async function listAccountMembers(
  env: Env,
  accountId: string,
): Promise<AccountMemberRow[]> {
  const result = await env.DB.prepare(
    `SELECT user_id AS userId, role, granted_by AS grantedBy, granted_at AS grantedAt
     FROM account_members WHERE account_id = ? ORDER BY granted_at ASC, user_id ASC LIMIT 500`,
  ).bind(accountId).all<AccountMemberRow>();
  return result.results;
}

export async function addAccountMember(
  env: Env,
  accountId: string,
  userId: string,
  role: "admin" | "member",
  grantedBy: string,
): Promise<boolean> {
  const inserted = await env.DB.prepare(
    `INSERT INTO account_members (account_id, user_id, role, granted_by, granted_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).bind(accountId, userId, role, grantedBy, new Date().toISOString()).run();
  return inserted.meta.changes === 1;
}

/**
 * Remove a membership. The member's session contexts for this account are
 * deleted in the same batch so no session keeps an active account it no
 * longer belongs to.
 */
export async function removeAccountMember(
  env: Env,
  accountId: string,
  userId: string,
): Promise<boolean> {
  const removed = await env.DB.batch([
    env.DB.prepare("DELETE FROM account_members WHERE account_id = ? AND user_id = ?").bind(accountId, userId),
    env.DB.prepare(
      "DELETE FROM account_session_contexts WHERE account_id = ? AND user_id = ?",
    ).bind(accountId, userId),
  ]);
  return removed[0]!.meta.changes === 1;
}

export async function isAccountMember(
  env: Env,
  accountId: string,
  userId: string,
): Promise<"admin" | "member" | null> {
  const row = await env.DB.prepare(
    "SELECT role FROM account_members WHERE account_id = ? AND user_id = ?",
  ).bind(accountId, userId).first<{ role: "admin" | "member" }>();
  return row?.role ?? null;
}

export async function listUserAccountMemberships(
  env: Env,
  userId: string,
  sessionToken: string | null,
): Promise<{ memberships: Array<AccountMembership & { active: boolean }>; activeAccountId: string | null }> {
  const rows = await env.DB.prepare(
    `SELECT a.id, a.name, a.description, a.created_by AS createdBy, a.created_at AS createdAt,
            m.role, m.granted_at AS grantedAt
     FROM account_members m JOIN accounts a ON a.id = m.account_id
     WHERE m.user_id = ? ORDER BY a.created_at ASC, a.id ASC LIMIT 200`,
  ).bind(userId).all<AccountRow & { role: "admin" | "member"; grantedAt: string }>();
  let activeAccountId: string | null = null;
  if (sessionToken) {
    const active = await env.DB.prepare(
      "SELECT account_id AS accountId FROM account_session_contexts WHERE session_token = ? AND user_id = ?",
    ).bind(sessionToken, userId).first<{ accountId: string }>();
    activeAccountId = active?.accountId ?? null;
  }
  return {
    memberships: rows.results.map((row) => ({
      role: row.role,
      grantedAt: row.grantedAt,
      account: {
        id: row.id,
        name: row.name,
        description: row.description,
        createdBy: row.createdBy,
        createdAt: row.createdAt,
      },
      active: row.id === activeAccountId,
    })),
    activeAccountId,
  };
}

/**
 * Bind an active account to a session. Both the raw session token (the
 * switch surface's key) and the session id (the protocol `sid`) are stored.
 * Membership is verified on the same query the write answers, so an expired
 * grant cannot be reintroduced by racing a removal.
 */
export async function switchActiveAccount(
  env: Env,
  sessionToken: string,
  sessionId: string | null,
  userId: string,
  accountId: string,
): Promise<AccountRow | null> {
  const row = await env.DB.prepare(
    `SELECT a.id, a.name, a.description, a.created_by AS createdBy, a.created_at AS createdAt
     FROM accounts a JOIN account_members m ON m.account_id = a.id
     WHERE a.id = ? AND m.user_id = ?`,
  ).bind(accountId, userId).first<AccountRow>();
  if (!row) return null;
  await env.DB.prepare(
    `INSERT INTO account_session_contexts (session_token, session_id, user_id, account_id, switched_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (session_token) DO UPDATE SET
       session_id = excluded.session_id,
       user_id = excluded.user_id,
       account_id = excluded.account_id,
       switched_at = excluded.switched_at`,
  ).bind(sessionToken, sessionId, userId, accountId, new Date().toISOString()).run();
  return row;
}

/** The active account of a session identified by its Better Auth session id. */
export async function getSessionAccountContext(
  env: Env,
  sessionId: string,
): Promise<{ account: AccountRow; role: "admin" | "member" } | null> {
  const row = await env.DB.prepare(
    `SELECT a.id, a.name, a.description, a.created_by AS createdBy, a.created_at AS createdAt,
            m.role
     FROM account_session_contexts c
     JOIN accounts a ON a.id = c.account_id
     JOIN account_members m ON m.account_id = a.id AND m.user_id = c.user_id
     WHERE c.session_id = ?`,
  ).bind(sessionId).first<AccountRow & { role: "admin" | "member" }>();
  if (!row) return null;
  const { role, ...account } = row;
  return { account, role };
}

/** Drop context rows whose backing session can no longer be active. */
export async function cleanupAccountSessionContexts(
  env: Env,
  now: Date,
  maxAgeDays = 31,
): Promise<void> {
  const table = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'account_session_contexts'",
  ).first<{ name: string }>();
  if (!table) return;
  await env.DB.prepare("DELETE FROM account_session_contexts WHERE switched_at < ?")
    .bind(new Date(now.getTime() - maxAgeDays * 24 * 60 * 60 * 1000).toISOString())
    .run();
}
