/**
 * OpenID Connect Client-Initiated Backchannel Authentication (CIBA) — poll
 * mode store. The client authenticates and pushes an authentication request
 * through the backchannel endpoint; the user approves on a signed-in page
 * (no redirect flows exist in CIBA). The auth_req_id is a high-entropy bearer
 * value stored only as a SHA-256 digest. Fail-closed behind ENABLE_CIBA:
 * routes and the token grant extension both check the flag. Poll-mode only,
 * matching the deployment's notification surface (email).
 */

import type { Env } from "../env";

export const CIBA_GRANT = "urn:openid:params:grant-type:ciba";

/** Backchannel requests are short: the user must act within minutes. */
export const CIBA_REQUEST_TTL_SECONDS = 300;
export const CIBA_POLL_INTERVAL_SECONDS = 5;
/** A user cannot drown in pending approvals; a client cannot hoard them. */
export const MAX_PENDING_CIBA_PER_USER = 5;
const MAX_PENDING_CIBA_PER_CLIENT = 20;
const MAX_BINDING_MESSAGE_LENGTH = 128;

export interface CibaRequest {
  clientId: string;
  userId: string;
  scopes: string[];
  bindingMessage: string;
  status: "pending" | "approved" | "denied" | "consumed";
  sessionId: string | null;
  intervalSeconds: number;
  expiresAt: number;
}

export interface CibaIssuance {
  authReqId: string;
  expiresInSeconds: number;
  intervalSeconds: number;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function randomToken(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => byte % 64).map((value) => {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    return alphabet[value]!;
  }).join("");
}

/** The binding message is shown to the user verbatim: strip control chars. */
export function normalizeBindingMessage(input: string | undefined): string {
  const value = (input ?? "").trim().replace(/[\u0000-\u001f\u007f]/g, "");
  return value.slice(0, MAX_BINDING_MESSAGE_LENGTH);
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Create a backchannel authentication request. A user cap keeps the approval
 * page (and the notification surface) bounded; a client cap contains hoarding.
 */
export async function createCibaRequest(
  env: Env,
  input: { clientId: string; userId: string; scopes: string[]; bindingMessage: string },
): Promise<CibaIssuance> {
  const pendingForUser = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM oauth_ciba_requests WHERE user_id = ? AND status = 'pending' AND expires_at > ?",
  ).bind(input.userId, nowSeconds()).first<{ count: number }>();
  if ((pendingForUser?.count ?? 0) >= MAX_PENDING_CIBA_PER_USER) throw new Error("ciba_user_cap_reached");
  const pendingForClient = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM oauth_ciba_requests WHERE client_id = ? AND status = 'pending' AND expires_at > ?",
  ).bind(input.clientId, nowSeconds()).first<{ count: number }>();
  if ((pendingForClient?.count ?? 0) >= MAX_PENDING_CIBA_PER_CLIENT) throw new Error("ciba_client_cap_reached");
  const authReqId = randomToken(43);
  const now = nowSeconds();
  const result = await env.DB.prepare(
    `INSERT INTO oauth_ciba_requests
       (auth_req_id_hash, client_id, user_id, scopes, binding_message, status,
        interval_seconds, last_poll_at, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, 0, ?, ?)`,
  ).bind(await sha256Hex(authReqId), input.clientId, input.userId, JSON.stringify(input.scopes),
    input.bindingMessage, CIBA_POLL_INTERVAL_SECONDS, Date.now(), (now + CIBA_REQUEST_TTL_SECONDS) * 1000).run();
  if (!result.success) throw new Error("CIBA request storage failed");
  return { authReqId, expiresInSeconds: CIBA_REQUEST_TTL_SECONDS, intervalSeconds: CIBA_POLL_INTERVAL_SECONDS };
}

const CIBA_COLUMNS = "client_id, user_id, scopes, binding_message, status, session_id, interval_seconds, expires_at";
interface CibaRow {
  client_id: string;
  user_id: string;
  scopes: string;
  binding_message: string;
  status: CibaRequest["status"];
  session_id: string | null;
  interval_seconds: number;
  expires_at: number;
}

function rowToRequest(raw: CibaRow): CibaRequest {
  return {
    clientId: raw.client_id,
    userId: raw.user_id,
    scopes: JSON.parse(raw.scopes) as string[],
    bindingMessage: raw.binding_message,
    status: raw.status,
    sessionId: raw.session_id,
    intervalSeconds: raw.interval_seconds,
    expiresAt: raw.expires_at,
  };
}

export async function loadCibaRequest(env: Env, authReqId: string): Promise<CibaRequest | null> {
  const raw = await env.DB.prepare(
    `SELECT ${CIBA_COLUMNS} FROM oauth_ciba_requests WHERE auth_req_id_hash = ?`,
  ).bind(await sha256Hex(authReqId)).first<CibaRow>();
  if (!raw || raw.expires_at < Date.now()) return null;
  return rowToRequest(raw);
}

/** Pending approvals for one user (the approval page). */
export async function listPendingCibaRequests(env: Env, userId: string): Promise<Array<CibaRequest & { id: string }>> {
  const result = await env.DB.prepare(
    `SELECT auth_req_id_hash, ${CIBA_COLUMNS} FROM oauth_ciba_requests
     WHERE user_id = ? AND status = 'pending' AND expires_at > ?
     ORDER BY created_at ASC LIMIT ${MAX_PENDING_CIBA_PER_USER}`,
  ).bind(userId, nowSeconds()).all<CibaRow & { auth_req_id_hash: string }>();
  return result.results.map((row) => ({ ...rowToRequest(row), id: row.auth_req_id_hash }));
}

/**
 * Approve or deny one pending request. The caller passes only the row id (the
 * digest); the hash comparison makes the update target unambiguous. The
 * conditional update makes double-approval a no-op.
 */
export async function decideCibaRequest(
  env: Env,
  requestIdHash: string,
  userId: string,
  approve: boolean,
  sessionId: string,
): Promise<boolean> {
  const status = approve ? "approved" : "denied";
  const result = await env.DB.prepare(
    `UPDATE oauth_ciba_requests SET status = ?, session_id = ?
     WHERE auth_req_id_hash = ? AND user_id = ? AND status = 'pending' AND expires_at > ?`,
  ).bind(status, sessionId, requestIdHash, userId, Date.now()).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("CIBA request decision failed");
  return result.meta.changes === 1;
}

/** Poll bookkeeping (same semantics as the device grant). */
export async function cibaPollIntervalViolated(env: Env, authReqId: string, intervalSeconds: number): Promise<boolean> {
  const hash = await sha256Hex(authReqId);
  const now = Date.now();
  const raw = await env.DB.prepare("SELECT last_poll_at FROM oauth_ciba_requests WHERE auth_req_id_hash = ?")
    .bind(hash).first<{ last_poll_at: number }>();
  const lastPollAt = raw?.last_poll_at ?? 0;
  await env.DB.prepare("UPDATE oauth_ciba_requests SET last_poll_at = ? WHERE auth_req_id_hash = ?")
    .bind(now, hash).run();
  return lastPollAt > 0 && now - lastPollAt < intervalSeconds * 1000;
}

/** Single-use consumption for an approved request. */
export async function consumeCibaRequest(env: Env, authReqId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE oauth_ciba_requests SET status = 'consumed'
     WHERE auth_req_id_hash = ? AND status = 'approved' AND expires_at > ?`,
  ).bind(await sha256Hex(authReqId), Date.now()).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("CIBA consumption failed");
  return result.meta.changes === 1;
}

export async function cleanupCibaRequests(env: Env, now: Date): Promise<number> {
  const result = await env.DB.prepare("DELETE FROM oauth_ciba_requests WHERE expires_at < ? OR status IN ('denied', 'consumed')")
    .bind(now.getTime()).run();
  return result.meta?.changes ?? 0;
}
