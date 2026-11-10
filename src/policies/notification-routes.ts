/**
 * Notification rule management (docs/design/authentik-policies.md): rules carry
 * transports and are bound to event-matcher policies through the standard
 * binding engine (target `notification_rule`).
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { validateTransports, type NotificationTransport } from "./notifications";

export const notificationRuleRoutes = new Hono<{ Bindings: Env }>();

notificationRuleRoutes.get("/notification-rules", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const rows = await context.env.DB.prepare(
    `SELECT id, name, transports, enabled, created_at AS createdAt
     FROM notification_rules ORDER BY name ASC LIMIT 200`,
  ).all<Record<string, unknown>>();
  return context.json({
    rules: rows.results.map((row) => ({
      ...row,
      transports: JSON.parse((row.transports as string) ?? "[]") as NotificationTransport[],
      enabled: row.enabled === 1,
    })),
  });
});

notificationRuleRoutes.post("/notification-rules", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  const name = typeof value.name === "string" ? value.name.trim() : "";
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) {
    return context.json({ error: "name must be 1-64 characters from [A-Za-z0-9_.-]" }, 400);
  }
  let transports: NotificationTransport[];
  try {
    transports = validateTransports(value.transports);
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "Invalid transports" }, 400);
  }
  return auditStandaloneOperation(context.env, "policy.notification_rule.create", "/api/admin/notification-rules", async () => {
    const duplicate = await context.env.DB.prepare("SELECT id FROM notification_rules WHERE name = ?").bind(name).first();
    if (duplicate) {
      return { response: Response.json({ error: "A rule with that name exists" }, { status: 409 }), actorUserId: admin.userId };
    }
    const id = crypto.randomUUID();
    await context.env.DB.prepare(
      `INSERT INTO notification_rules (id, name, transports, enabled, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(id, name, JSON.stringify(transports), value.enabled === false ? 0 : 1, admin.userId, new Date().toISOString()).run();
    return {
      response: Response.json({ rule: { id, name, transports, enabled: value.enabled !== false } }, { status: 201 }),
      actorUserId: admin.userId,
      targetUserId: name,
    };
  });
});

notificationRuleRoutes.delete("/notification-rules/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  return auditStandaloneOperation(context.env, "policy.notification_rule.delete", context.req.path, async () => {
    const removed = await context.env.DB.prepare("DELETE FROM notification_rules WHERE id = ?").bind(id).run();
    return {
      response: removed.meta.changes === 1 ? Response.json({ deleted: true }) : Response.json({ error: "Rule not found" }, { status: 404 }),
      actorUserId: admin.userId,
      targetUserId: id,
    };
  });
});
