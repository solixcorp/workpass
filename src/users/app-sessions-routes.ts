import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { appSessionSnapshot, logoutUserFromApps, presentSessions } from "../oauth/app-logout";

export const appSessionsRoutes = new Hono<{ Bindings: Env }>();

appSessionsRoutes.use("/api/*", async (c, next) => { c.header("Cache-Control", "no-store"); await next(); });

appSessionsRoutes.get("/api/admin/users/:id/app-sessions", async (c) => {
  const admin = await requireAdministrator(c);
  if (admin instanceof Response) return admin;
  const id = c.req.param("id");
  if (!await c.env.DB.prepare('SELECT id FROM "user" WHERE id = ?').bind(id).first()) return c.json({ error: "사용자를 찾을 수 없습니다." }, 404);
  return c.json({ apps: presentSessions(await appSessionSnapshot(c.env, id)) });
});

appSessionsRoutes.post("/api/admin/users/:id/app-sessions/revoke", async (c) => {
  const admin = await requireAdministrator(c);
  if (admin instanceof Response) return admin;
  const id = c.req.param("id");
  if (!await c.env.DB.prepare('SELECT id FROM "user" WHERE id = ?').bind(id).first()) return c.json({ error: "사용자를 찾을 수 없습니다." }, 404);
  const body = await c.req.json().catch(() => null) as { clientId?: unknown; forgetConsent?: unknown } | null;
  if (!body || typeof body !== "object" || Array.isArray(body) || (body.clientId !== undefined && (typeof body.clientId !== "string" || !body.clientId)) || (body.forgetConsent !== undefined && typeof body.forgetConsent !== "boolean")) return c.json({ error: "요청 형식이 올바르지 않습니다." }, 400);
  return auditStandaloneOperation(c.env, "identity.user.app_sessions_revoke", c.req.path, async () => {
    const result = await logoutUserFromApps(c.env, id, { clientId: body.clientId as string | undefined, forgetConsent: body.forgetConsent as boolean | undefined, reason: "admin" });
    return { response: result.error ? Response.json({ error: "앱 세션을 종료할 수 없습니다." }, { status: 503 }) : Response.json(result), actorUserId: admin.userId, targetUserId: id };
  });
});

appSessionsRoutes.get("/api/me/connected-apps", async (c) => {
  const session = await createAuth(c.env).api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ error: "로그인이 필요합니다." }, 401);
  const snapshot = await appSessionSnapshot(c.env, session.user.id);
  const consents = (await c.env.DB.prepare('SELECT clientId, scopes, createdAt FROM "oauthConsent" WHERE userId = ?').bind(session.user.id)
    .all<{ clientId: string; scopes: string; createdAt: string | number | null }>()).results;
  const apps = presentSessions(snapshot);
  for (const client of snapshot.clients) {
    if (consents.some((x) => x.clientId === client.clientId) && !apps.some((x) => x.clientId === client.clientId)) {
      apps.push({ clientId: client.clientId, slug: client.slug, applicationName: client.applicationName, activeTokens: 0, lastIssuedAt: null, backchannelLogout: !!client.backchannelLogoutUri });
    }
  }
  return c.json({ apps: apps.map((app) => {
    const matching = consents.filter((x) => x.clientId === app.clientId);
    const scopes = new Set<string>();
    for (const consent of matching) { try { const v = JSON.parse(consent.scopes); if (Array.isArray(v)) for (const s of v) if (typeof s === "string") scopes.add(s); } catch { /* malformed record */ } }
    const dates = matching.map((x) => typeof x.createdAt === "number" ? x.createdAt : x.createdAt && /^\d+$/.test(x.createdAt) ? Number(x.createdAt) : Date.parse(x.createdAt ?? "")).filter(Number.isFinite);
    return { ...app, consentGrantedAt: dates.length ? new Date(Math.min(...dates)).toISOString() : null, scopes: [...scopes] };
  }) });
});

appSessionsRoutes.delete("/api/me/connected-apps/:clientId", async (c) => {
  const session = await createAuth(c.env).api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ error: "로그인이 필요합니다." }, 401);
  if (c.req.header("origin") !== new URL(c.env.AUTH_BASE_URL).origin) return c.json({ error: "요청을 처리할 수 없습니다." }, 403);
  const clientId = c.req.param("clientId");
  const snapshot = await appSessionSnapshot(c.env, session.user.id);
  const consent = await c.env.DB.prepare('SELECT 1 FROM "oauthConsent" WHERE userId = ? AND clientId = ?').bind(session.user.id, clientId).first();
  if (!consent && !snapshot.active.some((t) => t.clientId === clientId)) return c.json({ error: "앱을 찾을 수 없습니다." }, 404);
  const result = await logoutUserFromApps(c.env, session.user.id, { clientId, forgetConsent: true, reason: "self_disconnect", snapshot });
  if (result.error) return c.json({ error: "앱 세션을 종료할 수 없습니다." }, 503);
  return c.json({ revokedTokens: result.revokedTokens, status: result.apps[0]?.status ?? "failed" });
});
