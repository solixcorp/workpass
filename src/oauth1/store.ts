import type { Env } from "../env";
import { sealString, unsealString } from "../crypto/sealed";
import { cleanupOAuth1Nonces, ensureOAuth1NonceTable } from "./nonce-store";

/**
 * D1 storage for the OAuth 1.0a server (RFC 5849, HMAC-SHA1 profile).
 * Consumer, temporary-token and access-token secrets are all sealed at rest.
 * Temporary credentials expire; the scheduled cleanup prunes them. Access
 * tokens are long-lived and must be revoked explicitly (or on offboarding).
 */

export interface OAuth1Consumer {
  consumerKey: string;
  consumerSecret: string;
  consumerName: string;
  disabled: boolean;
}

export interface OAuth1TemporaryToken {
  token: string;
  consumerKey: string;
  callback: string;
  verifier: string;
  secret: string | null; // unsealed only for signature verification
  userId: string | null;
  approved: boolean;
  expiresAt: number;
  expired: boolean;
}

interface ConsumerRow {
  consumer_key: string;
  consumer_name: string;
  sealed_secret: string;
  disabled: number;
}

interface TemporaryTokenRow {
  token: string;
  consumer_key: string;
  callback: string;
  verifier: string;
  sealed_secret: string;
  user_id: string | null;
  approved_at: number | null;
  expires_at: number;
}

interface AccessTokenRow {
  token: string;
  consumer_key: string;
  user_id: string;
  sealed_secret: string;
  revoked: number;
  expires_at: number | null;
}

export const OAUTH1_TEMPORARY_TTL_SECONDS = 600;

function randomToken(prefix: string): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `${prefix}${btoa(String.fromCharCode(...bytes)).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_")}`;
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000);
const epochSeconds = (value: number): number => value > 1e11 ? Math.floor(value / 1000) : value;
const expirySecondsSql = "CASE WHEN expires_at > 100000000000 THEN CAST(expires_at / 1000 AS INTEGER) ELSE expires_at END";

const tablesReady = new WeakMap<D1Database, Promise<void>>();

export function ensureOAuth1Tables(db: D1Database): Promise<void> {
  const existing = tablesReady.get(db);
  if (existing) return existing;
  const ready = (async () => {
    await db.prepare(`CREATE TABLE IF NOT EXISTS oauth1_consumers (
      consumer_key TEXT PRIMARY KEY NOT NULL,
      consumer_name TEXT NOT NULL,
      sealed_secret TEXT NOT NULL,
      disabled INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    )`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS oauth1_temporary_tokens (
      token TEXT PRIMARY KEY NOT NULL,
      consumer_key TEXT NOT NULL,
      callback TEXT NOT NULL,
      verifier TEXT NOT NULL,
      sealed_secret TEXT NOT NULL,
      user_id TEXT,
      approved_at INTEGER,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS oauth1_access_tokens (
      token TEXT PRIMARY KEY NOT NULL,
      consumer_key TEXT NOT NULL,
      user_id TEXT NOT NULL,
      sealed_secret TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      expires_at INTEGER
    )`).run();
    await ensureOAuth1NonceTable(db);
  })();
  tablesReady.set(db, ready);
  ready.catch(() => tablesReady.delete(db));
  return ready;
}

export async function createConsumer(env: Env, consumerName: string): Promise<OAuth1Consumer> {
  await ensureOAuth1Tables(env.DB);
  const consumerKey = randomToken("ock_");
  const consumerSecret = randomToken("ocs_");
  const sealed = await sealString(env, consumerSecret, "internal-auth:oauth1:consumer");
  await env.DB.prepare(`INSERT INTO oauth1_consumers (consumer_key, consumer_name, sealed_secret, disabled, created_at)
    VALUES (?, ?, ?, 0, ?)`)
    .bind(consumerKey, consumerName, sealed, nowSeconds()).run();
  return { consumerKey, consumerSecret, consumerName, disabled: false };
}

export async function setConsumerDisabled(env: Env, consumerKey: string, disabled: boolean): Promise<boolean> {
  await ensureOAuth1Tables(env.DB);
  const result = await env.DB.prepare("UPDATE oauth1_consumers SET disabled = ? WHERE consumer_key = ?")
    .bind(disabled ? 1 : 0, consumerKey).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Consumer update failed");
  return result.meta.changes === 1;
}

export async function resolveOAuth1Consumer(env: Env, consumerKey: string): Promise<OAuth1Consumer | null> {
  await ensureOAuth1Tables(env.DB);
  const row = await env.DB.prepare("SELECT consumer_key, consumer_name, sealed_secret, disabled FROM oauth1_consumers WHERE consumer_key = ?")
    .bind(consumerKey).first<ConsumerRow>();
  if (!row || row.disabled === 1) return null;
  return {
    consumerKey: row.consumer_key, consumerName: row.consumer_name, disabled: false,
    consumerSecret: await unsealString(env, row.sealed_secret, "internal-auth:oauth1:consumer"),
  };
}

export async function issueTemporaryToken(env: Env, consumerKey: string, callback: string): Promise<Omit<OAuth1TemporaryToken, "secret"> & { secret: string }> {
  await ensureOAuth1Tables(env.DB);
  const token = randomToken("oat_");
  const secret = randomToken("ots_");
  const verifier = randomToken("ovf_");
  const createdAt = nowSeconds();
  const expiresAt = createdAt + OAUTH1_TEMPORARY_TTL_SECONDS;
  const result = await env.DB.prepare(`INSERT INTO oauth1_temporary_tokens
    (token, consumer_key, callback, verifier, sealed_secret, user_id, approved_at, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)`)
    .bind(token, consumerKey, callback, verifier, await sealString(env, secret, "internal-auth:oauth1:temporary"),
      createdAt, expiresAt).run();
  if (!result.success || result.meta?.changes !== 1) throw new Error("Temporary token storage failed");
  return { token, consumerKey, callback, verifier, secret, userId: null, approved: false,
    expiresAt, expired: false };
}

export async function loadTemporaryToken(env: Env, token: string): Promise<OAuth1TemporaryToken | null> {
  await ensureOAuth1Tables(env.DB);
  const raw = await env.DB.prepare(
    "SELECT token, consumer_key, callback, verifier, sealed_secret, user_id, approved_at, expires_at FROM oauth1_temporary_tokens WHERE token = ?",
  ).bind(token).first<TemporaryTokenRow>();
  if (!raw) return null;
  const expiresAt = epochSeconds(raw.expires_at);
  const expired = expiresAt <= nowSeconds();
  return {
    token: raw.token, consumerKey: raw.consumer_key, callback: raw.callback, verifier: raw.verifier,
    secret: expired ? null : await unsealString(env, raw.sealed_secret, "internal-auth:oauth1:temporary"),
    userId: raw.user_id, approved: raw.approved_at !== null, expiresAt, expired,
  };
}

/** Single approval: the conditional update makes double-approval a no-op. */
export async function approveTemporaryToken(env: Env, token: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE oauth1_temporary_tokens SET user_id = ?, approved_at = ? WHERE token = ? AND user_id IS NULL AND approved_at IS NULL AND ${expirySecondsSql} > ?`,
  ).bind(userId, nowSeconds(), token, nowSeconds()).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Temporary token approval failed");
  return result.meta.changes === 1;
}

export async function rejectTemporaryToken(env: Env, token: string): Promise<boolean> {
  const result = await env.DB.prepare(`DELETE FROM oauth1_temporary_tokens WHERE token = ? AND user_id IS NULL AND approved_at IS NULL AND ${expirySecondsSql} > ?`)
    .bind(token, nowSeconds()).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Temporary token rejection failed");
  return result.meta.changes === 1;
}

/** Atomically consume the approved receipt after signature and verifier validation. */
export async function consumeTemporaryToken(env: Env, token: string, consumerKey: string, userId: string, verifier: string): Promise<boolean> {
  const row = await env.DB.prepare(`DELETE FROM oauth1_temporary_tokens WHERE token = ? AND consumer_key = ? AND user_id = ? AND verifier = ? AND approved_at IS NOT NULL AND ${expirySecondsSql} > ? RETURNING token`)
    .bind(token, consumerKey, userId, verifier, nowSeconds()).first<{ token: string }>();
  return row !== null;
}

export interface OAuth1AccessToken {
  token: string;
  consumerKey: string;
  userId: string;
  secret: string;
}

/** Single-use access token issuance. */
export async function issueAccessToken(env: Env, consumerKey: string, userId: string): Promise<OAuth1AccessToken> {
  await ensureOAuth1Tables(env.DB);
  const token = randomToken("oac_");
  const secret = randomToken("acs_");
  const sealed = await sealString(env, secret, "internal-auth:oauth1:access");
  const result = await env.DB.prepare(`INSERT INTO oauth1_access_tokens
    (token, consumer_key, user_id, sealed_secret, revoked, created_at, expires_at)
    VALUES (?, ?, ?, ?, 0, ?, NULL)`)
    .bind(token, consumerKey, userId, sealed, nowSeconds()).run();
  if (!result.success || result.meta?.changes !== 1) throw new Error("Access token storage failed");
  return { token, secret, consumerKey, userId };
}

/** Credential resolution for access-token (and later resource) requests. */
export async function resolveOAuth1AccessToken(env: Env, token: string): Promise<OAuth1AccessToken | null> {
  await ensureOAuth1Tables(env.DB);
  const raw = await env.DB.prepare("SELECT token, consumer_key, user_id, sealed_secret, revoked, expires_at FROM oauth1_access_tokens WHERE token = ?")
    .bind(token).first<AccessTokenRow>();
  if (!raw || raw.revoked === 1) return null;
  if (raw.expires_at !== null && epochSeconds(raw.expires_at) <= nowSeconds()) return null;
  return {
    token: raw.token, consumerKey: raw.consumer_key, userId: raw.user_id,
    secret: await unsealString(env, raw.sealed_secret, "internal-auth:oauth1:access"),
  };
}

export async function revokeOAuth1AccessToken(env: Env, token: string): Promise<boolean> {
  const result = await env.DB.prepare("UPDATE oauth1_access_tokens SET revoked = 1 WHERE token = ? AND revoked = 0")
    .bind(token).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Access token revocation failed");
  return result.meta.changes === 1;
}

/** Remove a user's access tokens and pending credentials during offboarding. */
export async function revokeOAuth1UserTokens(env: Env, userId: string): Promise<number> {
  await ensureOAuth1Tables(env.DB);
  const results = await env.DB.batch([
    env.DB.prepare("DELETE FROM oauth1_access_tokens WHERE user_id = ?").bind(userId),
    env.DB.prepare("DELETE FROM oauth1_temporary_tokens WHERE user_id = ?").bind(userId),
  ]);
  if (results.some((result) => !result.success || typeof result.meta?.changes !== "number")) throw new Error("User token revocation failed");
  return results.reduce((total, result) => total + result.meta.changes, 0);
}

export async function cleanupOAuth1Temporaries(env: Env, nowMs: number): Promise<void> {
  if (!Number.isSafeInteger(nowMs)) throw new Error("Invalid cleanup time");
  await ensureOAuth1Tables(env.DB);
  const now = Math.floor(nowMs / 1000);
  await env.DB.prepare(`DELETE FROM oauth1_temporary_tokens WHERE ${expirySecondsSql} <= ?`).bind(now).run();
  await cleanupOAuth1Nonces(env.DB, now);
}
