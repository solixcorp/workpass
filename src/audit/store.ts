import type { Env } from "../env";
import { notifySecurityEvent } from "../users/security-notices";
import { auditRequestContext } from "./request-context";

export type AuditOutcome = "started" | "success" | "failure";

export interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_user_id: string | null;
  target_user_id: string | null;
  event_type: string;
  outcome: AuditOutcome;
  request_path: string;
  /** New in the policy-framework era; covered by content-hash v2. */
  client_ip?: string | null;
  /** JSON-serializable context snapshot for event matching. */
  event_context?: Record<string, unknown> | null;
}

/**
 * The tamper-evidence hash: v2 adds the client IP and the event-context JSON
 * so the policy framework's matcher surface stays covered by the chain.
 */
/**
 * Tamper evidence over the audit content: a per-entry hash recomputed and
 * verified by walking the log. Rows are never deleted before one year, and D1
 * itself is NOT claimed to be immutable — the hash detects modification or
 * deletion of finalized rows when operators verify the log or exports.
 *
 * v2 adds the client IP and the event-context JSON (both fields the policy
 * framework's event matcher reads); rows written by newer code carry
 * hash_version 2 while legacy rows keep v1.
 */
export async function auditContentHash(
  fields: AuditEvent & { hash?: string | null },
  version: number,
): Promise<string> {
  const canonical = JSON.stringify([
    fields.id,
    fields.occurred_at,
    fields.actor_user_id,
    fields.target_user_id,
    fields.event_type,
    fields.outcome,
    fields.request_path,
    ...(version >= 2 ? [fields.client_ip ?? null, fields.event_context ?? null] : []),
  ]);
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return toBase64(new Uint8Array(bytes));
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function insertAuditEvent(
  env: Env,
  event: Pick<AuditEvent, "id" | "actor_user_id" | "target_user_id" | "event_type" | "outcome" | "request_path"> &
    Partial<Pick<AuditEvent, "client_ip" | "event_context">>,
): Promise<void> {
  const occurredAt = new Date().toISOString();
  const request = auditRequestContext.getStore();
  const clientIp = event.client_ip === undefined ? request?.ip ?? null : event.client_ip;
  const eventContext = request?.geo ? { ...event.event_context, geo: request.geo } : event.event_context ?? undefined;
  const contentHash = await auditContentHash({ ...event, occurred_at: occurredAt, client_ip: clientIp, event_context: eventContext }, 2);
  // Single statement: the log position is assigned inside SQL so concurrent
  // inserts cannot claim the same position.
  await env.DB.prepare(
    `INSERT INTO audit_events
      (id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path,
       client_ip, event_context, hash_version, log_pos, content_hash)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, (SELECT COALESCE(MAX(log_pos), 0) + 1 FROM audit_events), ?`,
  )
    .bind(
      event.id,
      occurredAt,
      event.actor_user_id,
      event.target_user_id,
      event.event_type,
      event.outcome,
      event.request_path,
      clientIp,
      eventContext === undefined ? null : JSON.stringify(eventContext),
      contentHash,
    )
    .run();
  // Notification rules evaluate best-effort: enqueue failures must never
  // break the audit write (the deferred import avoids a module cycle).
  try {
    const { enqueueEventNotifications } = await import("../policies/notifications");
    await enqueueEventNotifications(env, {
      ...event,
      occurred_at: occurredAt,
      client_ip: clientIp,
      event_context: eventContext ?? null,
      hash_version: 2,
    } as AuditEvent & { hash_version: number });
  } catch {
    // Queue-less behavior is the documented failsafe.
  }
  if (event.outcome === "success") await notifySecurityEvent(env, event.event_type, event.target_user_id ?? event.actor_user_id);
}

export async function updateAuditEvent(
  env: Env,
  id: string,
  update: Pick<AuditEvent, "actor_user_id" | "target_user_id" | "outcome">,
): Promise<void> {
  const row = await env.DB.prepare(
    `SELECT id, occurred_at, event_type, request_path, client_ip, event_context,
            COALESCE(hash_version, 1) AS hash_version
     FROM audit_events WHERE id = ?`,
  ).bind(id).first<AuditEvent & { client_ip: string | null; event_context: string | null; hash_version: number }>();
  if (!row) throw new Error("Audit event is missing");
  const contentHash = await auditContentHash({
    ...row,
    event_context: row.event_context === null ? null : JSON.parse(row.event_context) as Record<string, unknown>,
    actor_user_id: update.actor_user_id,
    target_user_id: update.target_user_id,
    outcome: update.outcome,
  }, row.hash_version);
  const result = await env.DB.prepare(
    `UPDATE audit_events
     SET actor_user_id = ?, target_user_id = ?, outcome = ?, content_hash = ?
     WHERE id = ? AND outcome = 'started'`,
  )
    .bind(update.actor_user_id, update.target_user_id, update.outcome, contentHash, id)
    .run();
  if (result.meta.changes !== 1) {
    throw new Error("Audit event is missing or already finalized");
  }
  if (update.outcome === "success") await notifySecurityEvent(env, row.event_type, update.target_user_id ?? update.actor_user_id);
}

export interface AuditChainVerification {
  verified: boolean;
  entries: number;
  legacyEntries: number;
  firstProblem: string | null;
}

/** Walk every positioned entry: content hash must match and positions must be contiguous. */
export async function verifyAuditEventChain(env: Env): Promise<AuditChainVerification> {
  const rows = await env.DB.prepare(
    `SELECT id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path,
            log_pos, content_hash, client_ip, event_context,
            COALESCE(hash_version, 1) AS hash_version
     FROM audit_events WHERE log_pos IS NOT NULL ORDER BY log_pos ASC LIMIT 50000`,
  ).all<{
    id: string;
    occurred_at: string;
    actor_user_id: string | null;
    target_user_id: string | null;
    event_type: string;
    outcome: AuditOutcome;
    request_path: string;
    log_pos: number;
    content_hash: string | null;
    client_ip: string | null;
    event_context: string | null;
    hash_version: number;
  }>();
  const positioned = rows.results;
  let firstProblem: string | null = null;
  for (let index = 0; index < positioned.length; index += 1) {
    const row = positioned[index]!;
    const recomputed = await auditContentHash({
      ...row,
      event_context: row.event_context === null ? null : JSON.parse(row.event_context) as Record<string, unknown>,
    }, row.hash_version);
    if (recomputed !== row.content_hash) {
      firstProblem = `entry at log position ${row.log_pos} has a modified content hash`;
      break;
    }
    // Positions are assigned as MAX+1 at insert time, so a missing or
    // duplicated position means entries were removed or the log was replaced.
    if (row.log_pos !== index + 1) {
      firstProblem = `log positions are not contiguous at ${row.log_pos}`;
      break;
    }
  }
  const legacy = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM audit_events WHERE log_pos IS NULL",
  ).first<{ count: number }>();
  return {
    verified: firstProblem === null,
    entries: positioned.length,
    legacyEntries: legacy?.count ?? 0,
    firstProblem,
  };
}

export async function auditStandaloneOperation(
  env: Env,
  eventType: string,
  requestPath: string,
  operation: () => Promise<{
    response: Response;
    actorUserId?: string | null;
    targetUserId?: string | null;
  }>,
): Promise<Response> {
  const id = crypto.randomUUID();
  try {
    await insertAuditEvent(env, {
      id,
      actor_user_id: null,
      target_user_id: null,
      event_type: eventType,
      outcome: "started",
      request_path: requestPath,
    });
  } catch {
    return Response.json({ error: "Audit event could not be recorded" }, { status: 503 });
  }

  let result: Awaited<ReturnType<typeof operation>>;
  try {
    result = await operation();
  } catch (operationError) {
    console.error("audit standalone operation failed", operationError instanceof Error ? (operationError.stack ?? operationError.message) : String(operationError));
    try {
      await updateAuditEvent(env, id, {
        actor_user_id: null,
        target_user_id: null,
        outcome: "failure",
      });
    } catch {
      // Keep the started event for later reconciliation.
    }
    return Response.json({ error: "Operation failed", eventId: id }, { status: 500 });
  }

  try {
    await updateAuditEvent(env, id, {
      actor_user_id: result.actorUserId ?? null,
      target_user_id: result.targetUserId ?? null,
      outcome: result.response.ok ? "success" : "failure",
    });
  } catch {
    return Response.json(
      { error: "Operation audit finalization failed", eventId: id },
      { status: 503 },
    );
  }

  return result.response;
}
