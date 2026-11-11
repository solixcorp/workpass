/**
 * Outbound SCIM executor: the actual remote call for one persisted
 * operation, shared by the administrator route (synchronous execution) and
 * the daily Worker Cron dispatcher (pending-operation drain). Configuration
 * comes from the deployment bindings; credentials stay in the environment.
 */

import type { Env } from "../env";
import { createScimUser, patchScimUser, type ScimTarget } from "./client";
import { getObjectAttributes, type AttributeValue } from "../objects/attributes";
import { claimScimOperation, completeScimCreate, finishScimOperation, getScimOperation } from "./operations";
import { getScimUserMapping } from "./mappings";

export interface ScimExecutorConfig {
  targetId: string;
  target: ScimTarget;
}

/**
 * Resolve the single configured target. Fails closed unless provisioning is
 * enabled with a syntactically valid https (or dev-loopback) base URL.
 */
export function loadScimExecutorConfig(env: Env): ScimExecutorConfig | null {
  if (env.ENABLE_SCIM_PROVISIONING !== "true") return null;
  const targetId = env.SCIM_TARGET_ID;
  const baseUrl = env.SCIM_BASE_URL;
  const bearerToken = env.SCIM_BEARER_TOKEN;
  if (!targetId || !baseUrl || !bearerToken || !/^[A-Za-z0-9_-]{1,128}$/.test(targetId)) return null;
  try {
    const url = new URL(baseUrl);
    const protocolOk = url.protocol === "https:" ||
      (env.SCIM_DEV_LOOPBACK_TARGET === "true" && url.protocol === "http:" &&
        (url.hostname === "127.0.0.1" || url.hostname === "localhost"));
    if (!protocolOk || url.username || url.password || url.search || url.hash || !bearerToken.trim()) return null;
    return { targetId, target: { baseUrl, bearerToken, allowLoopbackHttp: env.SCIM_DEV_LOOPBACK_TARGET === "true" } };
  } catch {
    return null;
  }
}

/**
 * Execute one claimed operation against the remote target. Attribute
 * release rides on create/update only when the operator flag is set.
 */
export async function executeScimOperation(env: Env, config: ScimExecutorConfig, operationId: string): Promise<boolean> {
  const operation = await getScimOperation(env, operationId);
  if (!operation || operation.target_id !== config.targetId) return false;
  if ((await claimScimOperation(env, operationId)) === false) return false;
  const attributeRelease = env.ENABLE_SCIM_ATTRIBUTE_RELEASE === "true";  const mapped = await getScimUserMapping(env, config.targetId, operation.user_id);
  if ((operation.operation === "create" && mapped) || (operation.operation !== "create" && !mapped)) {
    await finishScimOperation(env, operationId, "failed");
    return false;
  }
  const user = await env.DB.prepare(
    'SELECT id, email, name, username FROM "user" WHERE id = ?',
  ).bind(operation.user_id).first<{ id: string; email: string; name: string; username: string | null }>();
  if (!user) {
    await finishScimOperation(env, operationId, "failed");
    return false;
  }
  const customAttributes: Record<string, AttributeValue> | undefined =
    operation.operation === "deactivate" || !attributeRelease
      ? undefined
      : (await getObjectAttributes(env, "user", operation.user_id)).attributes;
  const result = operation.operation === "create"
    ? await createScimUser(config.target, { externalId: user.id, userName: user.username || user.email, displayName: user.name, email: user.email, active: true, customAttributes })
    : await patchScimUser(config.target, mapped!, operation.operation === "deactivate"
      ? { active: false }
      : { userName: user.username || user.email, displayName: user.name, email: user.email, ...(config.targetId.startsWith("app:") ? { active: true } : {}), customAttributes });
  if (!result.ok) {
    const unknown = result.kind === "outcome_unknown" || result.kind === "invalid_response";
    await finishScimOperation(env, operationId, unknown ? "outcome_unknown" : "failed", result.status ?? null);
    return false;
  }
  if (operation.operation === "create") {
    const created = result.value as { id: string };
    if (!(await completeScimCreate(env, operationId, config.targetId, operation.user_id, created.id))) {
      await finishScimOperation(env, operationId, "outcome_unknown", 201);
      return false;
    }
    return true;
  }
  return await finishScimOperation(env, operationId, "succeeded");
}

/** Drain queued SCIM operations: claimed oldest-first, capped per run. */
export async function dispatchPendingScimOperations(env: Env, maxOperations = 50): Promise<number> {
  const config = loadScimExecutorConfig(env);
  if (!config) return 0;
  const pending = await env.DB.prepare(
    "SELECT id FROM scim_operations WHERE status = 'pending' AND target_id = ? ORDER BY created_at ASC, id ASC LIMIT ?",
  ).bind(config.targetId, maxOperations).all<{ id: string }>();
  let executed = 0;
  for (const row of pending.results) {
    let succeeded: boolean;
    try {
      succeeded = await executeScimOperation(env, config, row.id);
    } catch (error) {
      console.error("Pending SCIM operation execution failed", {
        operationId: row.id,
        name: error instanceof Error ? error.name : "UnknownError",
      });
      try { await finishScimOperation(env, row.id, "failed"); } catch { /* stays locked */ }
      continue;
    }
    if (succeeded) executed += 1;
  }
  return executed;
}

/**
 * Queue an attribute-propagation update for a user: one attempt per
 * configured target, best-effort (queue-full, unconfigured or flag-off cases
 * no-op and the next attribute write retries). Only pending-or-newer
 * operations pass the single-active constraint; an already-locked user is
 * left alone.
 */
export async function scheduleScimAttributeSync(env: Env, userId: string): Promise<boolean> {
  const config = loadScimExecutorConfig(env);
  if (!config || env.ENABLE_SCIM_ATTRIBUTE_RELEASE !== "true") return false;
  const mapped = await getScimUserMapping(env, config.targetId, userId);
  if (!mapped) return false;
  const { createScimOperation } = await import("./operations");
  const id = await createScimOperation(env, { targetId: config.targetId, userId, operation: "update" });
  return id !== null;
}
