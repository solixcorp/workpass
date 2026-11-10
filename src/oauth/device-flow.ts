/**
 * RFC 8628 Device Authorization Grant — server-side store. The device code is
 * a high-entropy bearer value, so it is stored only as a SHA-256 digest; the
 * user code is the surface a human types into the approval page and is stored
 * verbatim. Grants fail closed behind ENABLE_DEVICE_FLOW (routes and the token
 * grant extension both check the flag). State machine: pending → approved |
 * denied; approved grants are consumed exactly once by the token grant.
 */

import type { Env } from "../env";

export const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

/** RFC 8628 §3.1 recommends a ~5 minute validity window. */
export const DEVICE_GRANT_TTL_SECONDS = 600;
/** RFC 8628 §3.5 default polling interval. */
export const DEVICE_POLL_INTERVAL_SECONDS = 5;
/** Unambiguous characters: no 0/O/1/I (§6.1 user code recommendations). */
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LENGTH = 8;
/** A client cannot hoard pending grants: brute-force and resource guard. */
const MAX_ACTIVE_GRANTS_PER_CLIENT = 20;

export interface DeviceGrant {
  clientId: string;
  scopes: string[];
  status: "pending" | "approved" | "denied" | "consumed";
  userId: string | null;
  sessionId: string | null;
  intervalSeconds: number;
  expiresAt: number;
}

export interface DeviceGrantIssuance {
  deviceCode: string;
  userCode: string;
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

/** User code uses an unambiguous alphabet; grouped XXXX-XXXX for reading. */
function randomUserCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(USER_CODE_LENGTH));
  const characters = Array.from(bytes, (byte) => USER_CODE_ALPHABET[byte % USER_CODE_ALPHABET.length]!);
  return `${characters.slice(0, 4).join("")}-${characters.slice(4).join("")}`;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Create a device grant for a client. Fail-closed on a hoarding client: past
 * the active-grant cap, creation is refused (the caller answers invalid_client
 * or a rate-limit error, not a new grant).
 */
export async function createDeviceGrant(env: Env, clientId: string, scopes: string[]): Promise<DeviceGrantIssuance> {
  const active = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM oauth_device_grants WHERE client_id = ? AND status = 'pending' AND expires_at > ?",
  ).bind(clientId, nowSeconds()).first<{ count: number }>();
  if ((active?.count ?? 0) >= MAX_ACTIVE_GRANTS_PER_CLIENT) {
    throw new Error("device_grant_cap_reached");
  }
  let userCode = randomUserCode();
  for (let attempts = 0; attempts < 8; attempts += 1) {
    // user_code is UNIQUE; on the (astronomically rare) collision, regenerate.
    const existing = await env.DB.prepare("SELECT 1 AS x FROM oauth_device_grants WHERE user_code = ?")
      .bind(userCode).first();
    if (!existing) break;
    userCode = randomUserCode();
  }
  const deviceCode = randomToken(43);
  const now = nowSeconds();
  const result = await env.DB.prepare(
    `INSERT INTO oauth_device_grants
       (device_code_hash, user_code, client_id, scopes, status, interval_seconds,
        last_poll_at, created_at, expires_at)
     VALUES (?, ?, ?, ?, 'pending', ?, 0, ?, ?)`,
  ).bind(await sha256Hex(deviceCode), userCode, clientId, JSON.stringify(scopes),
    DEVICE_POLL_INTERVAL_SECONDS, Date.now(), (now + DEVICE_GRANT_TTL_SECONDS) * 1000).run();
  if (!result.success) throw new Error("Device grant storage failed");
  return { deviceCode, userCode, expiresInSeconds: DEVICE_GRANT_TTL_SECONDS, intervalSeconds: DEVICE_POLL_INTERVAL_SECONDS };
}

/** Canonicalization: accept XXXX-XXXX and XXXXXXXX, uppercase, trim. */
export function normalizeUserCode(input: string): string {
  const compact = input.trim().toUpperCase().replace(/[\s-]/g, "");
  if (compact.length !== USER_CODE_LENGTH) return input.trim().toUpperCase();
  return `${compact.slice(0, 4)}-${compact.slice(4)}`;
}

/** Resolve a grant from the user code (pending lookups from the approval page). */
export async function loadDeviceGrantByUserCode(env: Env, userCode: string): Promise<DeviceGrant | null> {
  const raw = await env.DB.prepare(
    "SELECT client_id, scopes, status, user_id, session_id, interval_seconds, expires_at FROM oauth_device_grants WHERE user_code = ?",
  ).bind(userCode).first<{ client_id: string; scopes: string; status: DeviceGrant["status"]; user_id: string | null; session_id: string | null; interval_seconds: number; expires_at: number }>();
  if (!raw || raw.expires_at < Date.now()) return null;
  return {
    clientId: raw.client_id,
    scopes: JSON.parse(raw.scopes) as string[],
    status: raw.status,
    userId: raw.user_id,
    sessionId: raw.session_id,
    intervalSeconds: raw.interval_seconds,
    expiresAt: raw.expires_at,
  };
}

/** Resolve a grant from the bearer device code (token polling). */
export async function loadDeviceGrantByCode(env: Env, deviceCode: string): Promise<DeviceGrant | null> {
  const raw = await env.DB.prepare(
    "SELECT client_id, scopes, status, user_id, session_id, interval_seconds, expires_at FROM oauth_device_grants WHERE device_code_hash = ?",
  ).bind(await sha256Hex(deviceCode)).first<{ client_id: string; scopes: string; status: DeviceGrant["status"]; user_id: string | null; session_id: string | null; interval_seconds: number; expires_at: number }>();
  if (!raw || raw.expires_at < Date.now()) return null;
  return {
    clientId: raw.client_id,
    scopes: JSON.parse(raw.scopes) as string[],
    status: raw.status,
    userId: raw.user_id,
    sessionId: raw.session_id,
    intervalSeconds: raw.interval_seconds,
    expiresAt: raw.expires_at,
  };
}

/**
 * Approve (or deny) one pending grant for one user. The conditional update
 * makes double-approval a no-op and rejects the token grant's already-decided
 * races. Binding `sessionId` ties the issued tokens to the approving browser
 * session, so offboarding and session revocation also kill them.
 */
export async function decideDeviceGrant(
  env: Env,
  userCode: string,
  approve: boolean,
  userId: string,
  sessionId: string,
): Promise<boolean> {
  const status = approve ? "approved" : "denied";
  const result = await env.DB.prepare(
    `UPDATE oauth_device_grants SET status = ?, user_id = ?, session_id = ?
     WHERE user_code = ? AND status = 'pending' AND expires_at > ?`,
  ).bind(status, userId, sessionId, userCode, Date.now()).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Device grant decision failed");
  return result.meta.changes === 1;
}

/** Poll bookkeeping: returns "deny" when the poll is faster than the interval. */
export async function deviceGrantPollIntervalViolated(env: Env, deviceCode: string, intervalSeconds: number): Promise<boolean> {
  const now = Date.now();
  const raw = await env.DB.prepare("SELECT last_poll_at FROM oauth_device_grants WHERE device_code_hash = ?")
    .bind(await sha256Hex(deviceCode)).first<{ last_poll_at: number }>();
  const lastPollAt = raw?.last_poll_at ?? 0;
  // RFC 8628 §3.5: must not poll before interval has elapsed; a client that
  // polls early twice gets slow_down. The first early poll writes a raised
  // interval so the violation compounds.
  await env.DB.prepare("UPDATE oauth_device_grants SET last_poll_at = ? WHERE device_code_hash = ?")
    .bind(now, await sha256Hex(deviceCode)).run();
  return lastPollAt > 0 && now - lastPollAt < intervalSeconds * 1000;
}

/** Single-use consumption: an approved grant issues tokens exactly once. */
export async function consumeDeviceGrant(env: Env, deviceCode: string): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE oauth_device_grants SET status = 'consumed'
     WHERE device_code_hash = ? AND status = 'approved' AND expires_at > ?`,
  ).bind(await sha256Hex(deviceCode), Date.now()).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Device grant consumption failed");
  return result.meta.changes === 1;
}

/** Scheduled cleanup: expired rows are dead weight, denied/finished ones too. */
export async function cleanupDeviceGrants(env: Env, now: Date): Promise<number> {
  const result = await env.DB.prepare("DELETE FROM oauth_device_grants WHERE expires_at < ? OR status IN ('denied', 'consumed')")
    .bind(now.getTime()).run();
  return result.meta?.changes ?? 0;
}
