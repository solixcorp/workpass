import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { getApplication, listVisibleApplications } from "../applications/store";
import { sealString, unsealString } from "../crypto/sealed";
import { createScimOperation } from "../scim/operations";
import { executeScimOperation } from "../scim/executor";

export const provisioningRoutes = new Hono<{ Bindings: Env }>();
provisioningRoutes.use("*", async (c, next) => {
  await next();
  if (/^\/api\/admin\/applications\/[^/]+\/provisioning(?:\/|$)/.test(c.req.path)) c.header("Cache-Control", "no-store");
});

interface Target { slug: string; base_url: string; sealed_token: string; enabled: number; last_test_at: string | null; last_test_ok: number | null; last_sync_at: string | null; sync_cursor: string | null }
const load = (env: Env, slug: string) => env.DB.prepare("SELECT * FROM app_provisioning_targets WHERE slug = ?").bind(slug).first<Target>();

/** Reject IP literals except public IPv4. DNS resolution and rebinding require network-level controls. */
export function validProvisioningUrl(value: string): boolean {
  try {
    const u = new URL(value);
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash || !host || host.includes(":") || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      const [a, b] = host.split(".").map(Number) as [number, number, number, number];
      if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return false;
    }
    return true;
  } catch { return false; }
}

async function view(env: Env, slug: string) {
  const [target, rows] = await Promise.all([
    load(env, slug),
    env.DB.prepare("SELECT status, COUNT(*) AS count FROM scim_operations WHERE target_id = ? GROUP BY status").bind(`app:${slug}`).all<{ status: string; count: number }>(),
  ]);
  const counts: Record<string, number> = { pending: 0, in_progress: 0, succeeded: 0, failed: 0, outcome_unknown: 0 };
  for (const row of rows.results) counts[row.status] = row.count;
  return { configured: !!target, enabled: target?.enabled === 1, baseUrlHost: target ? new URL(target.base_url).hostname : null, tokenSet: !!target?.sealed_token, lastTestAt: target?.last_test_at ?? null, lastTestOk: target?.last_test_ok == null ? null : target.last_test_ok === 1, counts, lastSyncAt: target?.last_sync_at ?? null, canStoreSecrets: !!env.AEAD_SEALING_KEY };
}

provisioningRoutes.get("/applications/:slug/provisioning", async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) return admin;
  const slug = c.req.param("slug"); if (!await getApplication(c.env, slug)) return c.json({ error: "Application not found" }, 404);
  return c.json(await view(c.env, slug));
});

provisioningRoutes.put("/applications/:slug/provisioning", async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) return admin;
  const slug = c.req.param("slug"); if (!await getApplication(c.env, slug)) return c.json({ error: "Application not found" }, 404);
  const body = await c.req.json().catch(() => null) as { baseUrl?: unknown; bearerToken?: unknown; enabled?: unknown } | null;
  const previous = await load(c.env, slug);
  if (typeof body?.baseUrl !== "string" || body.baseUrl.length > 2048 || !validProvisioningUrl(body.baseUrl) || typeof body.enabled !== "boolean" || (body.bearerToken !== undefined && (typeof body.bearerToken !== "string" || !body.bearerToken.trim() || body.bearerToken.length > 4096 || /[\u0000-\u0020\u007f]/.test(body.bearerToken))) || (!previous && body.bearerToken === undefined)) return c.json({ error: "설정을 확인해 주세요." }, 400);
  if (body.bearerToken !== undefined && !c.env.AEAD_SEALING_KEY) return c.json({ error: "서버에 AEAD_SEALING_KEY가 설정되어 있지 않아 비밀값을 저장할 수 없습니다. 배포 설정에 키를 먼저 넣으세요." }, 409);
  const sealed = typeof body.bearerToken === "string" ? await sealString(c.env, body.bearerToken, `provisioning:${slug}`) : previous!.sealed_token;
  return auditStandaloneOperation(c.env, "app.provisioning.update", c.req.path, async () => {
    const now = new Date().toISOString();
    await c.env.DB.prepare(`INSERT INTO app_provisioning_targets (slug, base_url, sealed_token, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(slug) DO UPDATE SET base_url=excluded.base_url, sealed_token=excluded.sealed_token, enabled=excluded.enabled, updated_at=excluded.updated_at, last_test_at=NULL, last_test_ok=NULL`).bind(slug, body.baseUrl, sealed, body.enabled ? 1 : 0, now, now).run();
    return { response: Response.json(await view(c.env, slug)), actorUserId: admin.userId, targetUserId: slug };
  });
});

provisioningRoutes.delete("/applications/:slug/provisioning", async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) return admin;
  const slug = c.req.param("slug"); if (!await getApplication(c.env, slug)) return c.json({ error: "Application not found" }, 404);
  return auditStandaloneOperation(c.env, "app.provisioning.delete", c.req.path, async () => {
    await c.env.DB.prepare("DELETE FROM app_provisioning_targets WHERE slug = ?").bind(slug).run();
    return { response: Response.json({ deleted: true }), actorUserId: admin.userId, targetUserId: slug };
  });
});

provisioningRoutes.post("/applications/:slug/provisioning/test", async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) return admin;
  const slug = c.req.param("slug"); const target = await load(c.env, slug); if (!target) return c.json({ error: "설정이 없습니다." }, 404);
  return auditStandaloneOperation(c.env, "app.provisioning.test", c.req.path, async () => {
    let outcome: { ok: boolean; httpStatus?: number; error?: string };
    try {
      const token = await unsealString(c.env, target.sealed_token, `provisioning:${slug}`);
      const url = new URL(target.base_url); url.pathname = `${url.pathname.replace(/\/+$/, "")}/ServiceProviderConfig`;
      const response = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: "application/scim+json" }, redirect: "manual", signal: AbortSignal.timeout(8000) });
      outcome = response.ok ? { ok: true, httpStatus: response.status } : { ok: false, httpStatus: response.status, error: "SCIM 서버가 요청을 거부했습니다." };
    } catch { outcome = { ok: false, error: "SCIM 서버에 연결하지 못했습니다." }; }
    await c.env.DB.prepare("UPDATE app_provisioning_targets SET last_test_at = ?, last_test_ok = ? WHERE slug = ?").bind(new Date().toISOString(), outcome.ok ? 1 : 0, slug).run();
    return { response: Response.json(outcome), actorUserId: admin.userId, targetUserId: slug };
  });
});

provisioningRoutes.post("/applications/:slug/provisioning/sync", async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) return admin;
  const slug = c.req.param("slug"); const target = await load(c.env, slug); if (!target || !target.enabled) return c.json({ error: "활성화된 설정이 없습니다." }, 409);
  return auditStandaloneOperation(c.env, "app.provisioning.sync", c.req.path, async () => {
    const locked = await c.env.DB.prepare("UPDATE app_provisioning_targets SET sync_lock = 1 WHERE slug = ? AND sync_lock = 0 AND enabled = 1").bind(slug).run();
    if (!locked.meta.changes) return { response: Response.json({ error: "동기화가 진행 중입니다." }, { status: 409 }), actorUserId: admin.userId, targetUserId: slug };
    try {
      const fresh = await load(c.env, slug); if (!fresh) throw new Error("Target removed");
      const token = await unsealString(c.env, fresh.sealed_token, `provisioning:${slug}`);
      const targetId = `app:${slug}`;
      const users = await c.env.DB.prepare('SELECT id, banned FROM "user" WHERE id > ? ORDER BY id LIMIT 50').bind(fresh.sync_cursor ?? "").all<{ id: string; banned: number | null }>();
      let succeeded = 0; let failed = 0;
      for (const user of users.results) {
        const mapping = await c.env.DB.prepare("SELECT 1 FROM scim_user_mappings WHERE target_id = ? AND user_id = ?").bind(targetId, user.id).first();
        const allowed = (user.banned === null || user.banned === 0) && (await listVisibleApplications(c.env, user.id)).some((app) => app.slug === slug);
        if (!allowed && !mapping) continue;
        const operation = await createScimOperation(c.env, { targetId, userId: user.id, operation: allowed ? (mapping ? "update" : "create") : "deactivate" });
        if (!operation) { failed++; continue; }
        try { if (await executeScimOperation(c.env, { targetId, target: { baseUrl: fresh.base_url, bearerToken: token } }, operation)) succeeded++; else failed++; }
        catch { failed++; /* retain the open operation for reconciliation */ }
      }
      const cursor = users.results.at(-1)?.id ?? fresh.sync_cursor ?? "";
      const rest = await c.env.DB.prepare('SELECT COUNT(*) AS count FROM "user" WHERE id > ?').bind(cursor).first<{ count: number }>();
      const remaining = rest?.count ?? 0;
      await c.env.DB.prepare("UPDATE app_provisioning_targets SET sync_cursor = ?, last_sync_at = ? WHERE slug = ?").bind(remaining ? cursor : null, new Date().toISOString(), slug).run();
      return { response: Response.json({ processed: users.results.length, succeeded, failed, remaining }), actorUserId: admin.userId, targetUserId: slug };
    } finally { await c.env.DB.prepare("UPDATE app_provisioning_targets SET sync_lock = 0 WHERE slug = ?").bind(slug).run(); }
  });
});
