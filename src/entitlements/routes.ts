import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { listEntitlements } from "./store";

export const entitlementRoutes = new Hono<{ Bindings: Env }>();
const base = "/applications/:slug/entitlements";
entitlementRoutes.use(`${base}*`, async (c, next) => { c.header("Cache-Control", "no-store"); await next(); });

async function application(env: Env, slug: string) {
  return env.DB.prepare("SELECT id, slug, enabled FROM applications WHERE slug = ?").bind(slug)
    .first<{ id: string; slug: string; enabled: number }>();
}
const missing = () => Response.json({ error: "앱 또는 권한을 찾을 수 없습니다." }, { status: 404 });
const invalid = () => Response.json({ error: "입력값을 확인해 주세요." }, { status: 400 });
const conflict = () => Response.json({ error: "이미 사용 중인 권한 키입니다." }, { status: 409 });
const note = "entitlements 클레임은 OIDC ID 토큰과 UserInfo, SAML 및 WS-Fed에 전달됩니다.";

entitlementRoutes.get(base, async (c) => {
  const actor = await requireAdministrator(c); if (actor instanceof Response) return actor;
  const app = await application(c.env, c.req.param("slug")); if (!app) return missing();
  return c.json({ entitlements: await listEntitlements(c.env, app), releaseNote: note });
});

function text(value: unknown, max: number): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

entitlementRoutes.post(base, async (c) => {
  const actor = await requireAdministrator(c); if (actor instanceof Response) return actor;
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object" || !/^[a-z0-9][a-z0-9_.:-]{0,63}$/.test(body.key) || typeof body.key !== "string" ||
      !text(body.name, 200) || (body.description !== undefined && (typeof body.description !== "string" || body.description.length > 2000))) return invalid();
  return auditStandaloneOperation(c.env, "app.entitlement.create", c.req.path, async () => {
    const app = await application(c.env, c.req.param("slug"));
    if (!app) return { response: missing(), actorUserId: actor.userId };
    if (await c.env.DB.prepare("SELECT id FROM app_entitlements WHERE application_id = ? AND key = ?").bind(app.id, body.key).first()) {
      return { response: conflict(), actorUserId: actor.userId };
    }
    const id = crypto.randomUUID();
    try {
      const result = await c.env.DB.prepare(`INSERT INTO app_entitlements (id, application_id, key, name, description)
        SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM app_entitlements WHERE application_id = ?) < 50`)
        .bind(id, app.id, body.key, body.name.trim(), body.description ?? "", app.id).run();
      if (!result.meta.changes) return { response: Response.json({ error: "앱당 권한은 최대 50개입니다." }, { status: 400 }), actorUserId: actor.userId };
    } catch (error) {
      const existing = await c.env.DB.prepare("SELECT id FROM app_entitlements WHERE application_id = ? AND key = ?").bind(app.id, body.key).first();
      if (!existing) throw error;
      return { response: conflict(), actorUserId: actor.userId };
    }
    return { response: Response.json({ entitlement: { id, key: body.key, name: body.name.trim(), description: body.description ?? "" } }, { status: 201 }), actorUserId: actor.userId };
  });
});

entitlementRoutes.put(`${base}/:id`, async (c) => {
  const actor = await requireAdministrator(c); if (actor instanceof Response) return actor;
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body !== "object" || "key" in body || !text(body.name, 200) ||
      (body.description !== undefined && (typeof body.description !== "string" || body.description.length > 2000))) return invalid();
  return auditStandaloneOperation(c.env, "app.entitlement.update", c.req.path, async () => {
    const app = await application(c.env, c.req.param("slug")); if (!app) return { response: missing(), actorUserId: actor.userId };
    const id = c.req.param("id");
    const current = await c.env.DB.prepare("SELECT id, key, name, description FROM app_entitlements WHERE id = ? AND application_id = ?").bind(id, app.id)
      .first<{ id: string; key: string; name: string; description: string }>();
    if (!current) return { response: missing(), actorUserId: actor.userId };
    const entitlement = { ...current, name: body.name.trim(), description: body.description ?? current.description };
    await c.env.DB.prepare("UPDATE app_entitlements SET name = ?, description = ? WHERE id = ? AND application_id = ?")
      .bind(entitlement.name, entitlement.description, id, app.id).run();
    return { response: Response.json({ entitlement }), actorUserId: actor.userId };
  });
});

entitlementRoutes.delete(`${base}/:id`, async (c) => {
  const actor = await requireAdministrator(c); if (actor instanceof Response) return actor;
  return auditStandaloneOperation(c.env, "app.entitlement.delete", c.req.path, async () => {
    const app = await application(c.env, c.req.param("slug")); if (!app) return { response: missing(), actorUserId: actor.userId };
    const result = await c.env.DB.prepare("DELETE FROM app_entitlements WHERE id = ? AND application_id = ?").bind(c.req.param("id"), app.id).run();
    return { response: result.meta.changes ? Response.json({ deleted: true }) : missing(), actorUserId: actor.userId };
  });
});

entitlementRoutes.put(`${base}/:id/groups`, async (c) => {
  const actor = await requireAdministrator(c); if (actor instanceof Response) return actor;
  const body = await c.req.json().catch(() => null);
  if (!body || !Array.isArray(body.groupIds) || body.groupIds.length > 500 || body.groupIds.some((id: unknown) => typeof id !== "string" || !id || id.length > 200)) return invalid();
  const ids = [...new Set<string>(body.groupIds)];
  return auditStandaloneOperation(c.env, "app.entitlement.assign", c.req.path, async () => {
    const app = await application(c.env, c.req.param("slug")); if (!app) return { response: missing(), actorUserId: actor.userId };
    const entitlementId = c.req.param("id");
    if (!await c.env.DB.prepare("SELECT id FROM app_entitlements WHERE id = ? AND application_id = ?").bind(entitlementId, app.id).first()) return { response: missing(), actorUserId: actor.userId };
    const groups: { id: string; name: string }[] = [];
    for (const id of ids) {
      const group = await c.env.DB.prepare("SELECT id, name FROM directory_groups WHERE id = ?").bind(id).first<{ id: string; name: string }>();
      if (!group) return { response: invalid(), actorUserId: actor.userId };
      groups.push(group);
    }
    await c.env.DB.batch([
      c.env.DB.prepare("DELETE FROM app_entitlement_groups WHERE entitlement_id = ?").bind(entitlementId),
      ...ids.map((id) => c.env.DB.prepare("INSERT INTO app_entitlement_groups (entitlement_id, group_id) VALUES (?, ?)").bind(entitlementId, id)),
    ]);
    groups.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    return { response: Response.json({ groups }), actorUserId: actor.userId };
  });
});
