/**
 * Notification rules (docs/design/authentik-policies.md): rule records bind
 * event-match policies (target `notification_rule`) and transports. Audit
 * writes enqueue matched rules into a durable pending queue (best-effort,
 * never blocking the audit write) and the scheduled worker drains it through
 * the configured transports.
 */

import type { Env } from "../env";
import type { AuditEvent } from "../audit/store";
import type { EventProjection, PolicyEvaluationContext } from "./types";
import { eventContextFromRow } from "./event-matcher";

import { evaluateBoundPolicies } from "./engine";


export interface NotificationTransportWebhook { kind: "webhook"; url: string }
export interface NotificationTransportEmail { kind: "email"; to: string }
export type NotificationTransport = NotificationTransportWebhook | NotificationTransportEmail;

export function validateTransports(raw: unknown): NotificationTransport[] {
  const value = (raw ?? []) as unknown[];
  if (!Array.isArray(raw) || value.length === 0 || value.length > 10) {
    throw new Error("transports must be a list of at most 10 entries");
  }
  return value.map((entry) => {
    if (typeof entry !== "object" || entry === null) throw new Error("each transport must be an object");
    const record = entry as Record<string, unknown>;
    if (record.kind === "webhook") {
      if (typeof record.url !== "string" || !/^https:\/\//.test(record.url)) {
        throw new Error("webhook transports need an https URL");
      }
      return { kind: "webhook", url: record.url } satisfies NotificationTransportWebhook;
    }
    if (record.kind === "email") {
      if (typeof record.to !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(record.to)) {
        throw new Error("email transports need a recipient address");
      }
      return { kind: "email", to: record.to } satisfies NotificationTransportEmail;
    }
    throw new Error("transports must be webhook or email");
  });
}

interface AuditRowEvent {
  id: string;
  occurred_at: string;
  event_type: string;
  client_ip?: string | null;
  event_context?: Record<string, unknown> | null;
}

/**
 * Evaluate the rules after an audit insert and enqueue matched ones. Called
 * from insertAuditEvent's deferred hook; failures are never fatal there.
 */
export async function enqueueEventNotifications(env: Env, event: AuditRowEvent): Promise<number> {
  const rules = await env.DB.prepare(
    "SELECT id FROM notification_rules WHERE enabled = 1 LIMIT 100",
  ).all<{ id: string }>();
  if (rules.results.length === 0) return 0;
  const ruleIds = rules.results.map((row) => row.id);
  const placeholders = ruleIds.map(() => "?").join(",");
  const boundRows = await env.DB.prepare(
    `SELECT DISTINCT target_ref FROM policy_bindings
     WHERE target = 'notification_rule' AND enabled = 1 AND target_ref IN (${placeholders})`,
  ).bind(...ruleIds).all<{ target_ref: string }>();
  const routed = new Set(boundRows.results.map((row) => row.target_ref));
  if (routed.size === 0) return 0;

  const projection = await eventProjectionFromRow(env, event);
  const context: PolicyEvaluationContext = {
    user: projection.user ? { ...projection.user, attributes: {}, roles: [] } : null,
    clientIp: projection.client_ip,
    subject: null,
    event: projection,
    context: {},
  };
  let queued = 0;
  for (const ruleId of ruleIds) {
    if (!routed.has(ruleId)) continue;
    const outcome = await evaluateBoundPolicies(env, "notification_rule", ruleId, context);
    if (!outcome.passing) continue;
    await env.DB.prepare(
      "INSERT INTO pending_event_notifications (id, rule_id, event_id, attempts, created_at) VALUES (?, ?, ?, 0, ?)",
    ).bind(crypto.randomUUID(), ruleId, event.id, new Date().toISOString()).run();
    queued += 1;
  }
  return queued;
}

async function eventProjectionFromRow(env: Env, event: AuditRowEvent): Promise<EventProjection> {
  let user: EventProjection["user"] = null;
  const actorId = (event as unknown as { actor_user_id?: string | null }).actor_user_id ?? null;
  if (actorId) {
    try {
      const row = await env.DB.prepare(
        'SELECT id, email, name, username FROM "user" WHERE id = ? LIMIT 1',
      ).bind(actorId).first<{ id: string; email: string; name: string; username: string | null }>();
      if (row) user = {
        pk: row.id, id: row.id, name: row.name,
        username: row.username ?? row.email, email: row.email,
        attributes: {}, roles: [],
      } satisfies EventProjection["user"] & Record<string, unknown>;
      void (null as unknown as EventProjection | null);
    } catch {
      // Partial storage degrades to a userless projection.
    }
  }
  return {
    action: event.event_type,
    event_uuid: event.id,
    app: event.event_type.split(".")[0] ?? "",
    client_ip: event.client_ip ?? null,
    user,
    context: event.event_context ?? eventContextFromRow(null),
    created: event.occurred_at,
  };
}

export interface DispatchSummary {
  dispatched: number;
  skipped: number;
}

/**
 * Drain the pending queue: each transport attempt is best-effort and a failed
 * attempt is retried by the next scheduled run, capped at five attempts.
 */
export async function dispatchPendingEventNotifications(env: Env, nowMs = Date.now()): Promise<DispatchSummary> {
  const rows = await env.DB.prepare(
    `SELECT n.id, n.rule_id, n.event_id, n.attempts, r.transports, e.event_type, e.occurred_at,
            e.actor_user_id AS actorUserId, e.request_path AS requestPath, e.client_ip, e.event_context
     FROM pending_event_notifications n
     JOIN notification_rules r ON r.id = n.rule_id AND r.enabled = 1
     JOIN audit_events e ON e.id = n.event_id
     ORDER BY n.created_at ASC LIMIT 100`,
  ).all<Record<string, unknown>>();
  let dispatched = 0;
  let skipped = 0;
  for (const row of rows.results) {
    const attempts = (row.attempts as number) ?? 0;
    if (attempts >= 5) {
      // Permanent failure: drop the row but leave the event in the audit log.
      await env.DB.prepare("DELETE FROM pending_event_notifications WHERE id = ?").bind(row.id).run();
      skipped += 1;
      continue;
    }
    const transports = (() => {
      try { return JSON.parse((row.transports as string) ?? "[]") as NotificationTransport[]; }
      catch { return [] as NotificationTransport[]; }
    })();
    const projection = {
      action: row.event_type as string,
      event_uuid: row.event_id as string,
      created: row.occurred_at as string,
      requestPath: row.requestPath as string,
      clientIp: row.client_ip as string | null,
    };
    let delivered = 0;
    let failed = 0;
    for (const transport of transports) {
      try {
        if (transport.kind === "webhook") {
          const response = await fetch(transport.url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              kind: "policy.event",
              action: projection.action,
              eventUuid: projection.event_uuid,
              occurredAt: projection.created,
              clientIp: projection.clientIp,
            }),
            signal: AbortSignal.timeout(5_000),
          });
          if (!response.ok) throw new Error(`webhook responded ${response.status}`);
          delivered += 1;
        } else {
          const { sendTransactionEmail } = await import("../mail/send");
          await sendTransactionEmail(env, {
            to: transport.to,
            subject: `policy event: ${projection.action}`,
            text: `Event ${projection.event_uuid} (${projection.action}) occurred at ${projection.created}.`,
          });
          delivered += 1;
        }
      } catch {
        failed += 1;
      }
    }
    if (failed === 0) {
      await env.DB.prepare("DELETE FROM pending_event_notifications WHERE id = ?").bind(row.id).run();
      dispatched += 1;
    } else {
      await env.DB.prepare(
        "UPDATE pending_event_notifications SET attempts = attempts + 1 WHERE id = ?",
      ).bind(row.id).run();
      skipped += 1;
    }
  }
  return { dispatched, skipped };
}

