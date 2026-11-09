/**
 * WS-Federation relying-party registration data. Enablement is a deliberate
 * administrator action and follows the same gates as the SAML provider
 * lifecycle. See docs/design/wsfed-profile.md for the supported subset.
 */

import type { Env } from "../env";

export interface WsfedRelyingParty {
  id: string;
  realm: string;
  replyUrl: string;
  enabled: boolean;
}

export function validateWsfedRelyingParty(input: WsfedRelyingParty): void {
  if (!input.id || input.id.length > 128 || !input.realm || input.realm.length > 2048) {
    throw new Error("Invalid WS-Federation relying-party identifier");
  }
  let reply: URL;
  try {
    reply = new URL(input.replyUrl);
  } catch {
    throw new Error("Invalid WS-Federation reply URL");
  }
  if (reply.protocol !== "https:" || reply.username || reply.password || reply.hash) {
    throw new Error("WS-Federation reply URL must be HTTPS without credentials or fragment");
  }
}

/** Read a registration by local ID regardless of its enabled state. */
export async function getWsfedRelyingParty(env: Env, id: string): Promise<WsfedRelyingParty | null> {
  const row = await env.DB.prepare(
    "SELECT id, realm, reply_url AS replyUrl, enabled FROM wsfed_relying_parties WHERE id = ?",
  ).bind(id).first<{ id: string; realm: string; replyUrl: string; enabled: number }>();
  if (!row) return null;
  return { id: row.id, realm: row.realm, replyUrl: row.replyUrl, enabled: row.enabled === 1 };
}

/** Look up an enabled registration by its untrusted wtrealm value. */
export async function getEnabledWsfedRelyingPartyByRealm(
  env: Env,
  realm: string,
): Promise<WsfedRelyingParty | null> {
  if (!realm || realm.length > 2048) return null;
  const row = await env.DB.prepare(
    "SELECT id, realm, reply_url AS replyUrl, enabled FROM wsfed_relying_parties WHERE realm = ? AND enabled = 1",
  ).bind(realm).first<{ id: string; realm: string; replyUrl: string; enabled: number }>();
  if (!row) return null;
  return { id: row.id, realm: row.realm, replyUrl: row.replyUrl, enabled: row.enabled === 1 };
}

export async function createWsfedRelyingParty(env: Env, input: Omit<WsfedRelyingParty, "enabled"> & { createdBy: string }): Promise<boolean> {
  validateWsfedRelyingParty({ ...input, enabled: false });
  const result = await env.DB.prepare(
    `INSERT OR IGNORE INTO wsfed_relying_parties (id, realm, reply_url, enabled, created_by, created_at)
     VALUES (?, ?, ?, 0, ?, ?)`,
  ).bind(input.id, input.realm, input.replyUrl, input.createdBy, new Date().toISOString()).run();
  return result.meta.changes === 1;
}

export async function setWsfedRelyingPartyEnabled(env: Env, id: string, enabled: boolean): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE wsfed_relying_parties SET enabled = ? WHERE id = ?",
  ).bind(enabled ? 1 : 0, id).run();
  return result.meta.changes === 1;
}
