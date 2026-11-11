import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { verifyAuditEventChain, type AuditEvent } from "./store";
import { akqlParse } from "../policies/akql";
import { akqlMatch } from "../policies/akql";
import { eventContextFromRow, eventMatcherEvaluate, validateEventMatcherConfig } from "../policies/event-matcher";
import { auditQueryExamples, auditQueryFields, AuditQueryError, compileAuditQuery } from "./query";
import { auditClientGeo } from "./request-context";

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

auditRoutes.get("/audit-events/fields", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  return context.json({ fields: auditQueryFields, examples: auditQueryExamples });
});

auditRoutes.get("/audit-events/:eventId", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;

  const event = await context.env.DB.prepare(
    `SELECT id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path, client_ip, event_context
     FROM audit_events WHERE id = ?`,
  )
    .bind(context.req.param("eventId"))
    .first<AuditEvent>();
  if (!event) return context.json({ error: "Audit event not found" }, 404);
  return context.json({ event: { ...event, client_geo: auditClientGeo(event.event_context) } });
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
  const advanced = query.get("query");
  if (advanced !== null) {
    try {
      const compiled = compileAuditQuery(advanced);
      clauses.push(compiled.sql);
      values.push(...compiled.params);
    } catch (error) {
      if (error instanceof AuditQueryError) return context.json({ error: error.message, position: error.position, detail: error.detail }, 400);
      throw error;
    }
  }
  const ip = query.get("ip");
  if (ip) { clauses.push("client_ip = ?"); values.push(ip); }
  const country = query.get("country");
  if (country) { clauses.push("CASE WHEN json_valid(event_context) THEN json_extract(event_context, '$.geo.country') END = ?"); values.push(country); }
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

  // Everything done by or to one user.
  const involved = query.get("userId");
  if (involved) {
    clauses.push("(actor_user_id = ? OR target_user_id = ?)");
    values.push(involved, involved);
  }

  // A family of events by prefix (for example `authentication.`), and a plain
  // text match over the type, the path and the address.
  const prefix = query.get("eventPrefix");
  if (prefix) {
    if (!/^[a-z0-9_.]{1,64}$/.test(prefix)) return context.json({ error: "eventPrefix is not valid" }, 400);
    clauses.push("event_type LIKE ?");
    values.push(`${prefix}%`);
  }
  const text = query.get("q");
  if (text) {
    const like = `%${text.slice(0, 100).replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    clauses.push("(event_type LIKE ? ESCAPE '\\' OR request_path LIKE ? ESCAPE '\\' OR client_ip LIKE ? ESCAPE '\\')");
    values.push(like, like, like);
  }

  const search = query.get("search");
  if (search !== null) {
    try { akqlParse(search); } catch (error) {
      return context.json({ error: error instanceof Error ? error.message : "invalid AKQL search" }, 400);
    }
  }

  // Page-numbered reading (`page`, 1-based) with a total; the cursor stays for
  // callers that walk the log in order.
  const rawPage = query.get("page");
  if (rawPage !== null && (!/^[0-9]+$/.test(rawPage) || Number(rawPage) < 1 || Number(rawPage) * limit > 100_000)) {
    return context.json({ error: "page must be a positive integer within the first 100000 events" }, 400);
  }
  const page = rawPage === null ? null : Number(rawPage);
  const filterWhere = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const filterValues = [...values];

  const cursor = query.get("cursor");
  if (cursor && page === null) {
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
  const total = page === null ? null : (await context.env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_events ${filterWhere}`)
    .bind(...filterValues).first<{ n: number }>())?.n ?? 0;
  const rows = await context.env.DB.prepare(
    `SELECT id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path,
            client_ip, event_context
     FROM audit_events ${where} ORDER BY occurred_at DESC, id DESC LIMIT ?${page === null ? "" : " OFFSET ?"}`,
  )
    .bind(...values, limit + 1, ...(page === null ? [] : [(page - 1) * limit]))
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
  // Who the people in this page are, so the screen can say names instead of ids.
  const ids = [...new Set(events.flatMap((row) => [row.actor_user_id, row.target_user_id]).filter((id): id is string => Boolean(id)))];
  const people = new Map<string, { name: string; email: string }>();
  if (ids.length > 0) {
    const found = await context.env.DB.prepare(`SELECT id, name, email FROM "user" WHERE id IN (${ids.map(() => "?").join(",")})`)
      .bind(...ids).all<{ id: string; name: string; email: string }>().catch(() => ({ results: [] as Array<{ id: string; name: string; email: string }> }));
    for (const person of found.results) people.set(person.id, { name: person.name, email: person.email });
  }
  return context.json({
    events: events.map((row) => ({
      actor: row.actor_user_id ? people.get(row.actor_user_id) ?? null : null,
      target: row.target_user_id ? people.get(row.target_user_id) ?? null : null,
      id: row.id, occurred_at: row.occurred_at, actor_user_id: row.actor_user_id,
      target_user_id: row.target_user_id, event_type: row.event_type,
      outcome: row.outcome, request_path: row.request_path,
      client_ip: row.client_ip ?? null, client_geo: auditClientGeo(row.event_context), event_context: row.event_context ?? null,
    })),
    limit,
    ...(page === null ? {} : { page, total }),
    nextCursor: hasMore && lastEvent ? lastEvent.id : null,
  });
});
