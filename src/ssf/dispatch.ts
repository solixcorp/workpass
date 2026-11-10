import { signSet, type SetClaims } from "./set";
import { ensureSsfSigningKey, importSsfPrivateKey } from "./keys";
import { deliverPush } from "./push";
import type { Env } from "../env";

/**
 * Outbound SSF dispatch: events are signed with the platform RS256 key,
 * delivered to operator-registered recipients over push, and every attempt is
 * recorded. Delivery uses a bounded exponential backoff; after the attempt
 * ceiling the delivery is marked abandoned, never silently dropped.
 */

export interface SsfRecipient {
  id: string;
  audience: string;
  endpoint: string;
  eventTypes: string[];
  deliveryToken: string | null;
  disabled: boolean;
}

interface RecipientRow {
  id: string;
  audience: string;
  endpoint: string;
  event_types: string;
  delivery_token: string | null;
  disabled: number;
}

interface DeliveryRow {
  id: string;
  recipient_id: string;
  set_id: string;
  set_token: string;
  state: string;
  attempts: number;
  next_attempt_at: number;
  last_status: number | null;
  last_error: string | null;
}

export const SSF_MAX_ATTEMPTS = 10;

// The table-creation cache is per database (WeakMap), not a process-wide
// singleton: tests and multi-tenant runtimes create SSF tables on several
// D1 instances in one process, and a shared promise would leave the second
// database without its tables.
const ensuredTables = new WeakMap<D1Database, Promise<void>>();

export function ensureSsfDispatchTables(db: D1Database): Promise<void> {
  let ensured = ensuredTables.get(db);
  if (!ensured) {
    ensured = ensureTables(db);
    ensuredTables.set(db, ensured);
  }
  return ensured;
}

async function ensureTables(db: D1Database): Promise<void> {
  await db.prepare(`CREATE TABLE IF NOT EXISTS ssf_recipients (
    id TEXT PRIMARY KEY NOT NULL,
    audience TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    event_types TEXT NOT NULL,
    delivery_token TEXT,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS ssf_deliveries (
    id TEXT PRIMARY KEY NOT NULL,
    recipient_id TEXT NOT NULL,
    set_id TEXT NOT NULL,
    set_token TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_status INTEGER,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`).run();
  await db.prepare("CREATE INDEX IF NOT EXISTS ssf_deliveries_pending_idx ON ssf_deliveries (state, next_attempt_at)").run();
}

export async function upsertSsfRecipient(
  env: Env, input: { id: string; audience: string; endpoint: string; eventTypes: string[]; deliveryToken?: string },
): Promise<void> {
  await ensureSsfDispatchTables(env.DB);
  await env.DB.prepare(`INSERT INTO ssf_recipients (id, audience, endpoint, event_types, delivery_token, disabled, created_at)
    VALUES (?, ?, ?, ?, ?, 0, ?)
    ON CONFLICT(id) DO UPDATE SET audience=excluded.audience, endpoint=excluded.endpoint,
      event_types=excluded.event_types, delivery_token=excluded.delivery_token, disabled=0`)
    .bind(input.id, input.audience, input.endpoint, JSON.stringify(input.eventTypes),
      input.deliveryToken ?? null, Date.now()).run();
}

export async function deleteSsfRecipient(env: Env, id: string): Promise<boolean> {
  await ensureSsfDispatchTables(env.DB);
  const result = await env.DB.prepare("DELETE FROM ssf_recipients WHERE id = ?").bind(id).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Recipient delete failed");
  return result.meta.changes > 0;
}

/** Every enabled recipient (bounded); used by automated event emitters. */
export async function listEnabledSsfRecipients(env: Env, limit = 200): Promise<SsfRecipient[]> {
  await ensureSsfDispatchTables(env.DB);
  const rows = await env.DB.prepare(
    "SELECT id, audience, endpoint, event_types, delivery_token, disabled FROM ssf_recipients WHERE disabled = 0 LIMIT ?",
  ).bind(limit).all<RecipientRow>();
  return rows.results.map((row) => ({
    id: row.id, audience: row.audience, endpoint: row.endpoint,
    eventTypes: JSON.parse(row.event_types) as string[], deliveryToken: row.delivery_token, disabled: false,
  }));
}

async function loadSsfRecipient(env: Env, id: string): Promise<SsfRecipient | null> {
  const row = await env.DB.prepare(
    "SELECT id, audience, endpoint, event_types, delivery_token, disabled FROM ssf_recipients WHERE id = ?",
  ).bind(id).first<RecipientRow>();
  if (!row || row.disabled === 1) return null;
  return {
    id: row.id, audience: row.audience, endpoint: row.endpoint,
    eventTypes: JSON.parse(row.event_types) as string[], deliveryToken: row.delivery_token, disabled: false,
  };
}

function issuerFor(env: Env): string {
  return new URL(env.AUTH_BASE_URL).origin;
}

function validateEndpoint(endpoint: string): string {
  const url = new URL(endpoint);
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new Error("Recipient endpoint must be a https URL without credentials or fragment");
  }
  if (endpoint.length > 2048) throw new Error("Recipient endpoint must be at most 2048 characters");
  return endpoint;
}

/** Build, sign and dispatch one event to one recipient. The delivery row is
 * written before the network call so a crash cannot lose the event. */
export async function dispatchSSFEvent(
  env: Env,
  input: { recipientId: string; eventType: string; subject: Record<string, unknown>; description?: Record<string, unknown> },
  send: typeof fetch = fetch,
): Promise<{ state: string; status?: number; attempts: number }> {
  await ensureSsfDispatchTables(env.DB);
  const recipient = await loadSsfRecipient(env, input.recipientId);
  if (!recipient) throw new Error("Recipient not found");
  if (!recipient.eventTypes.includes(input.eventType)) {
    throw new Error("Event type is not enabled for this recipient");
  }
  const endpoint = validateEndpoint(recipient.endpoint);
  const key = await ensureSsfSigningKey(env);
  const signingKey = await importSsfPrivateKey(key.privateText);
  const claims: SetClaims = {
    iss: issuerFor(env),
    aud: recipient.audience,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    sub_id: input.subject,
    events: { [input.eventType]: input.description ?? {} },
  };
  const token = await signSet(claims, "ssf-1", signingKey);
  const attempts = 1;
  const result = await deliverPush(endpoint, token, recipient.deliveryToken ? `Bearer ${recipient.deliveryToken}` : undefined, send);
  const state = result.kind === "delivered" ? "delivered" : result.kind === "retry" ? "retry" : "failed";
  await env.DB.prepare(`INSERT INTO ssf_deliveries
    (id, recipient_id, set_id, set_token, state, attempts, next_attempt_at, last_status, last_error, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET set_token=excluded.set_token, state=excluded.state, attempts=excluded.attempts,
      next_attempt_at=excluded.next_attempt_at, last_status=excluded.last_status, updated_at=excluded.updated_at`)
    .bind(claims.jti, recipient.id, claims.jti, token, state, attempts, nextAttemptAt(result.kind === "retry" ? 1 : 0),
      result.status ?? null, null, Date.now(), Date.now()).run();
  return { state, status: result.status, attempts };
}

function nextAttemptAt(pastAttempts: number): number {
  const delaySeconds = Math.min(600 * (1 << pastAttempts), 6 * 3600);
  return Date.now() + delaySeconds * 1000;
}

/** Scheduled retry: bounded attempts, never silent abandonment. */
export async function attemptPendingSSFDispatch(env: Env, nowMs: number, limit = 20): Promise<void> {
  await ensureSsfDispatchTables(env.DB);
  if (!Number.isSafeInteger(nowMs)) throw new Error("Invalid dispatch time");
  const pending = await env.DB.prepare(
    `SELECT id, recipient_id, set_token, attempts FROM ssf_deliveries
     WHERE state = 'retry' AND next_attempt_at <= ? AND attempts < ? ORDER BY next_attempt_at LIMIT ?`,
  ).bind(nowMs, SSF_MAX_ATTEMPTS, limit).all<{ id: string; recipient_id: string; set_token: string; attempts: number }>();
  for (const row of pending.results ?? []) {
    const recipient = await loadSsfRecipient(env, row.recipient_id);
    if (!recipient) {
      await env.DB.prepare("UPDATE ssf_deliveries SET state = 'failed', last_error = 'recipient removed', updated_at = ? WHERE id = ?")
        .bind(Date.now(), row.id).run();
      continue;
    }
    try {
      const result = await deliverPush(recipient.endpoint, row.set_token, recipient.deliveryToken ?? undefined);
      const state = result.kind === "delivered" ? "delivered" : result.kind === "retry" ? "retry" : "failed";
      const attempts = row.attempts + 1;
      const abandoned = state !== "delivered" && attempts >= SSF_MAX_ATTEMPTS;
      await env.DB.prepare("UPDATE ssf_deliveries SET state = ?, attempts = ?, next_attempt_at = ?, last_status = ?, updated_at = ? WHERE id = ?")
        .bind(abandoned ? "abandoned" : state, attempts, nextAttemptAt(attempts - 1), result.status ?? null, Date.now(), row.id).run();
    } catch (error) {
      // Malformed stored token or endpoint: mark so the operator sees it.
      await env.DB.prepare("UPDATE ssf_deliveries SET state = 'failed', last_error = ?, updated_at = ? WHERE id = ?")
        .bind(error instanceof Error ? error.name : "delivery error", Date.now(), row.id).run();
    }
  }
}
