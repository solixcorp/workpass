import type { Env } from "../env";

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

/** Persist intent without credentials or profile data. Duplicate active work is refused. */
export async function createScimOperation(
  env: Env,
  input: { targetId: string; userId: string; operation: ScimOperationType },
): Promise<string | null> {
  if (!input.targetId || !input.userId) throw new Error("SCIM operation identifiers are required");
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    `INSERT OR IGNORE INTO scim_operations
     (id, target_id, user_id, operation, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
  ).bind(id, input.targetId, input.userId, input.operation, now, now).run();
  return result.meta.changes === 1 ? id : null;
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
