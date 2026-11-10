import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { verifyAuditEventChain, type AuditEvent } from "./store";
import { akqlParse } from "../policies/akql";
import { akqlMatch } from "../policies/akql";
import { eventContextFromRow, eventMatcherEvaluate, validateEventMatcherConfig } from "../policies/event-matcher";

export const auditRoutes = new Hono<{ Bindings: Env }>();

/** The authentik-compatible event projection used by AKQL search. */
async function eventProjection(env: Env, row: AuditEvent): Promise<Record<string, unknown>> {
  const actorUserId = (row as unknown as { actor_user_id?: string }).actor_user_id ?? null;
  let user: Record<string, unknown> | null = null;
  if (typeof actorUserId === "string" && actorUserId.length > 0) {
    try {
      user = (await env.DB.prepare('SELECT id, email, name, username FROM "user" WHERE id = ? LIMIT 1')
        .bind(actorUserId).first<Record<string, unknown>>()) ?? null;
    } catch {
      user = null;
    }
  }
  const contextRaw = (row as unknown as { event_context?: string | null }).event_context ?? null;
  const eventType = row.event_type;
  return {
    action: eventType,
    event_uuid: row.id,
    app: eventType.split(".")[0] ?? "",
    client_ip: (row as unknown as { client_ip?: string | null }).client_ip ?? null,
    outcome: row.outcome,
    created: row.occurred_at,
    user: user ? { pk: user.id, username:(user.username as string) ?? (user.email as string), email: user.email } : null,
    context: eventContextFromRow(contextRaw),
    request_path: row.request_path,
  };
}

auditRoutes.use("/audit-events/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

auditRoutes.use("/audit-events", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

// The verification route is declared before the :eventId route so "verify"
// is not swallowed as an event identifier.
auditRoutes.get("/audit-events/verify", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  const verification = await verifyAuditEventChain(context.env);
  return context.json({ verification });
});

auditRoutes.get("/audit-events/:eventId", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;

  const event = await context.env.DB.prepare(
    `SELECT id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path
     FROM audit_events WHERE id = ?`,
  )
    .bind(context.req.param("eventId"))
    .first<AuditEvent>();
  if (!event) return context.json({ error: "Audit event not found" }, 404);
  return context.json({ event });
});

auditRoutes.get("/audit-events", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;

  const query = new URL(context.req.url).searchParams;
  const rawLimit = query.get("limit");
  if (rawLimit !== null && (!/^[0-9]+$/.test(rawLimit) || Number(rawLimit) < 1 || Number(rawLimit) > 100)) {
    return context.json({ error: "limit must be an integer between 1 and 100" }, 400);
  }
  const limit = rawLimit === null ? 50 : Number(rawLimit);
  if (query.get("outcome") && !["started", "success", "failure"].includes(query.get("outcome")!)) {
    return context.json({ error: "outcome must be started, success, or failure" }, 400);
  }
  const from = query.get("from");
  const to = query.get("to");
  const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
  if (
    (from !== null && (!timestampPattern.test(from) || Number.isNaN(Date.parse(from)))) ||
    (to !== null && (!timestampPattern.test(to) || Number.isNaN(Date.parse(to))))
  ) {
    return context.json({ error: "from and to must be valid ISO-8601 timestamps" }, 400);
  }
  if (from && to && Date.parse(from) > Date.parse(to)) {
    return context.json({ error: "from must not be later than to" }, 400);
  }

  const clauses: string[] = [];
  const values: (string | number)[] = [];
  const exactFilters = [
    ["actorUserId", "actor_user_id"],
    ["targetUserId", "target_user_id"],
    ["eventType", "event_type"],
    ["outcome", "outcome"],
  ] as const;
  for (const [parameter, column] of exactFilters) {
    const value = query.get(parameter);
    if (value) {
      clauses.push(`${column} = ?`);
      values.push(value);
    }
  }
  for (const [value, operator] of [[from, ">="], [to, "<="]] as const) {
    if (value) {
      clauses.push(`occurred_at ${operator} ?`);
      values.push(new Date(value).toISOString());
    }
  }

  const search = query.get("search");
  if (search !== null) {
    try { akqlParse(search); } catch (error) {
      return context.json({ error: error instanceof Error ? error.message : "invalid AKQL search" }, 400);
    }
  }

  const cursor = query.get("cursor");
  if (cursor) {
    const cursorEvent = await context.env.DB.prepare(
      "SELECT occurred_at, id FROM audit_events WHERE id = ?",
    )
      .bind(cursor)
      .first<{ occurred_at: string; id: string }>();
    if (!cursorEvent) return context.json({ error: "Invalid audit cursor" }, 400);
    clauses.push("(occurred_at < ? OR (occurred_at = ? AND id < ?))");
    values.push(cursorEvent.occurred_at, cursorEvent.occurred_at, cursorEvent.id);
  }

  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await context.env.DB.prepare(
    `SELECT id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path,
            client_ip, event_context
     FROM audit_events ${where} ORDER BY occurred_at DESC, id DESC LIMIT ?`,
  )
    .bind(...values, limit + 1)
    .all<AuditEvent>();

  const hasMore = rows.results.length > limit;
  let events = (rows.results.slice(0, limit) as unknown as Array<AuditEvent & {
    client_ip?: string | null; event_context?: string | null;
  }>);
  // The AKQL search filter applies to the fetched page (a bounded deviation
  // from authentik's server-side search pagination).
  if (search !== null) {
    const projections: unknown[] = [];
    for (const row of events) {
      projections.push(await eventProjection(context.env, row as unknown as AuditEvent));
    }
    events = events.filter((_, index) => akqlMatch(search, projections[index] as Record<string, unknown>));
  }
  const lastEvent = events.at(-1);
  return context.json({
    events: events.map((row) => ({
      id: row.id, occurred_at: row.occurred_at, actor_user_id: row.actor_user_id,
      target_user_id: row.target_user_id, event_type: row.event_type,
      outcome: row.outcome, request_path: row.request_path,
      client_ip: row.client_ip ?? null, event_context: row.event_context ?? null,
    })),
    limit,
    nextCursor: hasMore && lastEvent ? lastEvent.id : null,
  });
});
