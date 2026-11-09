import type { Env } from "../env";

/** Persist only external identifiers; never store downstream bearer tokens here. */
export async function getScimUserMapping(env: Env, targetId: string, userId: string): Promise<string | null> {
  const row = await env.DB.prepare(
    "SELECT external_user_id FROM scim_user_mappings WHERE target_id = ? AND user_id = ?",
  ).bind(targetId, userId).first<{ external_user_id: string }>();
  return row?.external_user_id ?? null;
}

/** Refuse to replace a mapping implicitly: an unknown remote create outcome needs reconciliation. */
export async function recordScimUserMapping(
  env: Env,
  targetId: string,
  userId: string,
  externalUserId: string,
): Promise<boolean> {
  if (!targetId || !userId || !externalUserId) throw new Error("SCIM mapping identifiers are required");
  const result = await env.DB.prepare(
    `INSERT OR IGNORE INTO scim_user_mappings (target_id, user_id, external_user_id, created_at)
     VALUES (?, ?, ?, ?)`,
  ).bind(targetId, userId, externalUserId, new Date().toISOString()).run();
  return result.meta.changes === 1;
}
