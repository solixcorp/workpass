import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";

export type ScimOperationType = "create" | "update" | "deactivate";
export type ScimOperationStatus = "pending" | "in_progress" | "succeeded" | "failed" | "outcome_unknown";

export interface ScimOperation {
  id: string;
  target_id: string;
  user_id: string;
  operation: ScimOperationType;
  status: ScimOperationStatus;
  remote_status: number | null;
  created_at: string;
  updated_at: string;
}

/** Expiry never retries a remote mutation: its outcome must be reconciled. */
export async function expireScimLeases(env: Env, filter: { targetId?: string; userId?: string; now?: Date } = {}): Promise<void> {
  const now = filter.now ?? new Date();
  const cutoff = new Date(now.getTime() - 10 * 60_000).toISOString();
  const clauses = ["status = 'in_progress'", "updated_at < ?"];
  const values = [cutoff];
  if (filter.targetId !== undefined) { clauses.push("target_id = ?"); values.push(filter.targetId); }
  if (filter.userId !== undefined) { clauses.push("user_id = ?"); values.push(filter.userId); }
  const rows = await env.DB.prepare(`SELECT id, user_id FROM scim_operations WHERE ${clauses.join(" AND ")}`).bind(...values).all<{ id: string; user_id: string }>();
  for (const row of rows.results) {
    const response = await auditStandaloneOperation(env, "scim.operation.lease_expired", "/internal/scim/lease", async () => {
      const result = await env.DB.prepare("UPDATE scim_operations SET status = 'outcome_unknown', abandoned = 1, updated_at = ? WHERE id = ? AND status = 'in_progress' AND updated_at < ?").bind(now.toISOString(), row.id, cutoff).run();
      return { response: new Response(null, { status: result.meta.changes ? 204 : 409 }), targetUserId: row.user_id };
    });
    if (response.status !== 204 && response.status !== 409) throw new Error("SCIM lease expiry audit failed");
  }
}

/** Persist intent without credentials or profile data. Duplicate active work is refused. */
export async function createScimOperation(
  env: Env,
  input: { targetId: string; userId: string; operation: ScimOperationType },
): Promise<string | null> {
  if (!input.targetId || !input.userId) throw new Error("SCIM operation identifiers are required");
  await expireScimLeases(env, { targetId: input.targetId, userId: input.userId });
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  // A duplicate insert (the single-active-operation constraint) creates no
  // record; any other constraint failure must not masquerade as a duplicate.
  let changes: number;
  try {
    const result = await env.DB.prepare(
      `INSERT INTO scim_operations
       (id, target_id, user_id, operation, status, created_at, updated_at)
       SELECT ?, ?, ?, ?, 'pending', ?, ?
       WHERE NOT EXISTS (
         SELECT 1 FROM scim_operations
         WHERE target_id = ? AND user_id = ?
           AND status IN ('pending', 'in_progress', 'outcome_unknown')
       )`,
    ).bind(id, input.targetId, input.userId, input.operation, now, now, input.targetId, input.userId).run();
    changes = result.meta.changes;
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (!message.includes("UNIQUE constraint failed") && !message.includes("CHECK constraint failed")) throw error;
    changes = 0;
  }
  return changes === 1 ? id : null;
}

/** An atomic transition ensures only one worker can take an operation. */
export async function claimScimOperation(env: Env, id: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE scim_operations SET status = 'in_progress', updated_at = ? WHERE id = ? AND status = 'pending'",
  ).bind(new Date().toISOString(), id).run();
  return result.meta.changes === 1;
}

/** Unknown outcomes block subsequent mutations until an operator reconciles them. */
export async function finishScimOperation(
  env: Env,
  id: string,
  status: "succeeded" | "failed" | "outcome_unknown",
  remoteStatus: number | null = null,
): Promise<boolean> {
  if (remoteStatus !== null && (!Number.isInteger(remoteStatus) || remoteStatus < 100 || remoteStatus > 599)) {
    throw new Error("Invalid SCIM response status");
  }
  const result = await env.DB.prepare(
    `UPDATE scim_operations SET status = ?, remote_status = ?, updated_at = ?
     WHERE id = ? AND status = 'in_progress'`,
  ).bind(status, remoteStatus, new Date().toISOString(), id).run();
  return result.meta.changes === 1;
}

export async function getScimOperation(env: Env, id: string): Promise<ScimOperation | null> {
  return await env.DB.prepare(
    `SELECT id, target_id, user_id, operation, status, remote_status, created_at, updated_at
     FROM scim_operations WHERE id = ?`,
  ).bind(id).first<ScimOperation>();
}

/** Commit the external mapping and operation completion in one D1 transaction. */
export async function completeScimCreate(env: Env, id: string, targetId: string, userId: string, externalId: string): Promise<boolean> {
  const now = new Date().toISOString();
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT OR IGNORE INTO scim_user_mappings (target_id, user_id, external_user_id, created_at)
       SELECT ?, ?, ?, ? WHERE EXISTS (
         SELECT 1 FROM scim_operations WHERE id = ? AND target_id = ? AND user_id = ?
           AND operation = 'create' AND status = 'in_progress'
       )`,
    ).bind(targetId, userId, externalId, now, id, targetId, userId),
    env.DB.prepare(
      `UPDATE scim_operations SET status = 'succeeded', remote_status = 201, updated_at = ?
       WHERE id = ? AND target_id = ? AND user_id = ? AND operation = 'create' AND status = 'in_progress'
         AND changes() = 1
         AND EXISTS (SELECT 1 FROM scim_user_mappings WHERE target_id = ? AND user_id = ? AND external_user_id = ?)`,
    ).bind(now, id, targetId, userId, targetId, userId, externalId),
  ]);
  return results[0]?.meta.changes === 1 && results[1]?.meta.changes === 1;
}
