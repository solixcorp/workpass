/**
 * SWA application registration data. Enablement is a deliberate administrator
 * action; applications bind an exact HTTPS origin and never receive or store
 * application credentials (see docs/design/swa-workflow.md).
 */

import type { Env } from "../env";

export interface SwaApplication {
  id: string;
  name: string;
  origin: string;
  enabled: boolean;
}

const NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

export function validateSwaApplication(input: SwaApplication): void {
  if (!input.id || input.id.length > 128 || !NAME_PATTERN.test(input.name)) {
    throw new Error("Invalid SWA application identifier");
  }
  let parsed: URL;
  try {
    parsed = new URL(input.origin);
  } catch {
    throw new Error("Invalid SWA origin");
  }
  // Applications are bound to an exact HTTPS origin: no paths, credentials,
  // query, fragment, or user-identifying material; the origin string must be
  // the exact browser origin the application presents.
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error("SWA origin must be an exact HTTPS origin");
  }
}

/** Read a registration by local ID regardless of its enabled state. */
export async function getSwaApplication(env: Env, id: string): Promise<SwaApplication | null> {
  const row = await env.DB.prepare(
    "SELECT id, name, origin, enabled FROM swa_applications WHERE id = ?",
  ).bind(id).first<{ id: string; name: string; origin: string; enabled: number }>();
  if (!row) return null;
  return { id: row.id, name: row.name, origin: row.origin, enabled: row.enabled === 1 };
}

/** Look up an enabled registration by its untrusted origin value. */
export async function getEnabledSwaApplicationByOrigin(
  env: Env,
  origin: string,
): Promise<SwaApplication | null> {
  if (!origin || origin.length > 256) return null;
  const row = await env.DB.prepare(
    "SELECT id, name, origin, enabled FROM swa_applications WHERE origin = ? AND enabled = 1",
  ).bind(origin).first<{ id: string; name: string; origin: string; enabled: number }>();
  if (!row) return null;
  return { id: row.id, name: row.name, origin: row.origin, enabled: row.enabled === 1 };
}

/** A duplicate insert returns false; any other constraint failure throws. */
export async function createSwaApplication(env: Env, input: Omit<SwaApplication, "enabled"> & { createdBy: string }): Promise<boolean> {
  validateSwaApplication({ ...input, enabled: false });
  let changes: number;
  try {
    const result = await env.DB.prepare(
      `INSERT INTO swa_applications (id, name, origin, enabled, created_by, created_at)
       VALUES (?, ?, ?, 0, ?, ?)`,
    ).bind(input.id, input.name, input.origin, input.createdBy, new Date().toISOString()).run();
    changes = result.meta.changes;
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (!message.includes("UNIQUE constraint failed")) throw error;
    changes = 0;
  }
  return changes === 1;
}

export async function setSwaApplicationEnabled(env: Env, id: string, enabled: boolean): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE swa_applications SET enabled = ? WHERE id = ?",
  ).bind(enabled ? 1 : 0, id).run();
  return result.meta.changes === 1;
}

/**
 * Issue a single-use, five-minute grant. The nonce is created inside the
 * insert; only the acting user's session is trusted.
 */
export async function issueSwaGrant(env: Env, input: {
  applicationId: string;
  userId: string;
}): Promise<{ nonce: string; expiresAt: string }> {
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of nonceBytes) binary += String.fromCharCode(byte);
  const nonce = btoa(binary).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 5 * 60_000).toISOString();
  const result = await env.DB.prepare(
    `INSERT INTO swa_grants (nonce, application_id, user_id, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).bind(nonce, input.applicationId, input.userId, createdAt, expiresAt).run();
  if (result.meta.changes !== 1) throw new Error("SWA grant could not be recorded");
  return { nonce, expiresAt };
}

/** The scheduled handler may run before the SWA migration has been applied. */
export async function cleanupSwaGrants(env: Env, now = new Date()): Promise<void> {
  const table = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'swa_grants'",
  ).first<{ name: string }>();
  if (!table) return;
  await env.DB.prepare("DELETE FROM swa_grants WHERE expires_at <= ?")
    .bind(now.toISOString())
    .run();
}

/** Consume the nonce atomically: a replay, unknown or expired nonce rejects. */
export async function consumeSwaGrant(env: Env, nonce: string): Promise<{
  applicationId: string;
  userId: string;
  expiresAt: string;
} | null> {
  const result = await env.DB.prepare(
    `UPDATE swa_grants SET consumed_at = ?
     WHERE nonce = ? AND consumed_at IS NULL AND expires_at > ?`,
  ).bind(new Date().toISOString(), nonce, new Date().toISOString()).run();
  if (result.meta.changes !== 1) return null;
  const grant = await env.DB.prepare(
    "SELECT application_id AS applicationId, user_id AS userId, expires_at AS expiresAt FROM swa_grants WHERE nonce = ?",
  ).bind(nonce).first<{ applicationId: string; userId: string; expiresAt: string }>();
  if (!grant) return null;
  return grant;
}
