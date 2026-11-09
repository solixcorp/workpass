import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import type { AuditEvent } from "./store";

export const auditRoutes = new Hono<{ Bindings: Env }>();

auditRoutes.use("/audit-events/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

auditRoutes.use("/audit-events", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

auditRoutes.get("/audit-events/:eventId", async (context) => {
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  const role = (session.user as typeof session.user & { role?: unknown }).role;
  if (!(typeof role === "string" && role.split(",").includes("admin"))) {
    return context.json({ error: "Forbidden" }, 403);
  }

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
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  const role = (session.user as typeof session.user & { role?: unknown }).role;
  if (!(typeof role === "string" && role.split(",").includes("admin"))) {
    return context.json({ error: "Forbidden" }, 403);
  }

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
    `SELECT id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path
     FROM audit_events ${where} ORDER BY occurred_at DESC, id DESC LIMIT ?`,
  )
    .bind(...values, limit + 1)
    .all<AuditEvent>();

  const hasMore = rows.results.length > limit;
  const events = rows.results.slice(0, limit);
  const lastEvent = events.at(-1);
  return context.json({
    events,
    limit,
    nextCursor: hasMore && lastEvent ? lastEvent.id : null,
  });
});
