/** Administrator control of the places and the policy, and the public endpoint a browser reports its position to. */

import { Hono } from "hono";
import { auditStandaloneOperation } from "../audit/store";
import type { Env } from "../env";
import { requireAdministrator } from "./authorization";
import {
  evaluateLocation, listPlaces, loadLocationPolicy, networkPoint, parsePlaceIds, proofCookie, recordLocationProof, saveLocationPolicy,
  type LocationMode, type LocationPolicy, type LocationSignal,
} from "./location-policy";

export const locationAdminRoutes = new Hono<{ Bindings: Env }>();
export const locationPublicRoutes = new Hono<{ Bindings: Env }>();

locationAdminRoutes.use("/location/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

const MAX_PLACES = 100;

async function locationApplications(env: Env) {
  const rows = await env.DB.prepare("SELECT slug, name, protocol, binding FROM applications ORDER BY name, slug").all<{ slug: string; name: string; protocol: string; binding: string | null }>();
  return rows.results.flatMap((app) => app.binding && ["oidc", "saml", "wsfed"].includes(app.protocol) && /^[A-Za-z0-9_.:\/-]{1,2000}$/.test(app.binding) ? [{ subject: `${app.protocol}:${app.binding}`, name: app.name, slug: app.slug }] : []);
}

locationAdminRoutes.get("/location", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  context.header("Cache-Control", "no-store");
  const [policy, places, self] = await Promise.all([
    loadLocationPolicy(context.env),
    listPlaces(context.env),
    evaluateLocation(context.env, { request: context.req.raw, userId: admin.userId }),
  ]);
  const edge = networkPoint(context.req.raw);
  const groups = await context.env.DB.prepare("SELECT id, name FROM directory_groups ORDER BY name ASC LIMIT 200")
    .all<{ id: string; name: string }>().then((r) => r.results).catch(() => []);
  const [applications, groupRows, appRows] = await Promise.all([
    locationApplications(context.env),
    context.env.DB.prepare("SELECT group_id, place_ids FROM location_group_rules ORDER BY group_id").all<{ group_id: string; place_ids: string }>(),
    context.env.DB.prepare("SELECT subject, place_ids, mode FROM location_app_rules ORDER BY subject").all<{ subject: string; place_ids: string; mode: string }>(),
  ]);
  const groupRules = groupRows.results.map((row) => ({ groupId: row.group_id, groupName: groups.find((g) => g.id === row.group_id)?.name ?? null, placeIds: parsePlaceIds(row.place_ids) }));
  const appRules = appRows.results.map((row) => { const app = applications.find((a) => a.subject === row.subject); return { subject: row.subject, applicationName: app?.name ?? null, applicationSlug: app?.slug ?? null, placeIds: parsePlaceIds(row.place_ids), mode: row.mode }; });
  return context.json({
    policy, places, groups, groupRules, appRules, applications,
    edge: { available: edge !== null, country: edge?.country ?? null, city: edge?.city ?? null },
    // How this administrator's own connection fares against the policy right now.
    self,
  });
});

function validPlace(body: unknown): { name: string; latitude: number; longitude: number; radiusM: number; enabled: boolean } | { error: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: "요청 형식이 올바르지 않습니다." };
  const value = body as Record<string, unknown>;
  const name = typeof value.name === "string" ? value.name.trim() : "";
  if (!name || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) return { error: "장소 이름은 1자에서 80자 사이여야 합니다." };
  const latitude = Number(value.latitude);
  const longitude = Number(value.longitude);
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90) return { error: "위도는 -90에서 90 사이여야 합니다." };
  if (!Number.isFinite(longitude) || longitude < -180 || longitude > 180) return { error: "경도는 -180에서 180 사이여야 합니다." };
  const radiusM = Math.round(Number(value.radiusM));
  if (!Number.isFinite(radiusM) || radiusM < 50 || radiusM > 500_000) return { error: "반경은 50m에서 500km 사이여야 합니다." };
  return { name, latitude, longitude, radiusM, enabled: value.enabled !== false };
}

locationAdminRoutes.post("/location/places", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const place = validPlace(await context.req.json().catch(() => null));
  if ("error" in place) return context.json({ error: place.error }, 400);
  if ((await listPlaces(context.env)).length >= MAX_PLACES) return context.json({ error: `장소는 ${MAX_PLACES}개까지 만들 수 있습니다.` }, 409);
  const id = crypto.randomUUID();
  return auditStandaloneOperation(context.env, "location.place.create", context.req.path, async () => {
    const now = new Date().toISOString();
    await context.env.DB.prepare(
      "INSERT INTO location_places (id, name, latitude, longitude, radius_m, enabled, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(id, place.name, place.latitude, place.longitude, place.radiusM, place.enabled ? 1 : 0, admin.userId, now, now).run();
    return { response: Response.json({ place: { id, ...place } }, { status: 201 }), actorUserId: admin.userId, targetUserId: null };
  });
});

locationAdminRoutes.put("/location/places/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const place = validPlace(await context.req.json().catch(() => null));
  if ("error" in place) return context.json({ error: place.error }, 400);
  return auditStandaloneOperation(context.env, "location.place.update", context.req.path, async () => {
    const result = await context.env.DB.prepare(
      "UPDATE location_places SET name = ?, latitude = ?, longitude = ?, radius_m = ?, enabled = ?, updated_at = ? WHERE id = ?",
    ).bind(place.name, place.latitude, place.longitude, place.radiusM, place.enabled ? 1 : 0, new Date().toISOString(), id).run();
    const found = (result.meta?.changes ?? 0) > 0;
    return { response: found ? Response.json({ place: { id, ...place } }) : Response.json({ error: "장소를 찾을 수 없습니다." }, { status: 404 }), actorUserId: admin.userId, targetUserId: null };
  });
});

locationAdminRoutes.delete("/location/places/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  return auditStandaloneOperation(context.env, "location.place.delete", context.req.path, async () => {
    const result = await context.env.DB.prepare("DELETE FROM location_places WHERE id = ?").bind(id).run();
    await context.env.DB.prepare("DELETE FROM location_proofs WHERE place_id = ?").bind(id).run().catch(() => null);
    for (const [table, key] of [["location_group_rules", "group_id"], ["location_app_rules", "subject"]] as const) {
      const rows = await context.env.DB.prepare(`SELECT ${key} AS id, place_ids FROM ${table}`).all<{ id: string; place_ids: string }>();
      for (const row of rows.results) {
        const ids = parsePlaceIds(row.place_ids).filter((placeId) => placeId !== id);
        if (ids.length) await context.env.DB.prepare(`UPDATE ${table} SET place_ids = ? WHERE ${key} = ?`).bind(JSON.stringify(ids), row.id).run();
        else await context.env.DB.prepare(`DELETE FROM ${table} WHERE ${key} = ?`).bind(row.id).run();
      }
    }
    const found = (result.meta?.changes ?? 0) > 0;
    return { response: found ? Response.json({ deleted: true }) : Response.json({ error: "장소를 찾을 수 없습니다." }, { status: 404 }), actorUserId: admin.userId, targetUserId: null };
  });
});

async function checkedPlaceIds(env: Env, body: Record<string, unknown> | null): Promise<string[] | null> {
  if (!body || !Array.isArray(body.placeIds) || body.placeIds.length > MAX_PLACES || !body.placeIds.every((id) => typeof id === "string" && id.length > 0)) return null;
  const ids = [...new Set(body.placeIds as string[])];
  const places = await listPlaces(env);
  return ids.every((id) => places.some((place) => place.id === id)) ? ids : null;
}

locationAdminRoutes.put("/location/groups/:groupId", async (context) => {
  const admin = await requireAdministrator(context); if (admin instanceof Response) return admin;
  const groupId = context.req.param("groupId");
  const group = await context.env.DB.prepare("SELECT id FROM directory_groups WHERE id = ?").bind(groupId).first();
  if (!group) return context.json({ error: "그룹을 찾을 수 없습니다." }, 404);
  const ids = await checkedPlaceIds(context.env, await context.req.json().catch(() => null));
  if (!ids) return context.json({ error: "장소 목록이 올바르지 않습니다." }, 400);
  const policy = await loadLocationPolicy(context.env);
  const member = await context.env.DB.prepare("SELECT 1 FROM directory_group_members WHERE group_id = ? AND user_id = ?").bind(groupId, admin.userId).first();
  if (policy.mode === "enforce" && member) {
    const self = await evaluateLocation(context.env, { request: context.req.raw, userId: admin.userId, policy, groupOverride: { groupId, placeIds: ids } });
    if (!self.pass) return context.json({ error: "이 설정은 관리자 본인의 접속을 차단합니다.", code: self.needsBrowser ? "needs_browser" : "outside" }, 409);
  }
  return auditStandaloneOperation(context.env, "location.group_rule.update", context.req.path, async () => {
    if (ids.length) await context.env.DB.prepare("INSERT INTO location_group_rules (group_id, place_ids) VALUES (?, ?) ON CONFLICT(group_id) DO UPDATE SET place_ids = excluded.place_ids").bind(groupId, JSON.stringify(ids)).run();
    else await context.env.DB.prepare("DELETE FROM location_group_rules WHERE group_id = ?").bind(groupId).run();
    return { response: Response.json({ groupId, placeIds: ids }), actorUserId: admin.userId, targetUserId: null };
  });
});

locationAdminRoutes.delete("/location/groups/:groupId", async (context) => {
  const admin = await requireAdministrator(context); if (admin instanceof Response) return admin;
  return auditStandaloneOperation(context.env, "location.group_rule.delete", context.req.path, async () => {
    await context.env.DB.prepare("DELETE FROM location_group_rules WHERE group_id = ?").bind(context.req.param("groupId")).run();
    return { response: Response.json({ deleted: true }), actorUserId: admin.userId, targetUserId: null };
  });
});

locationAdminRoutes.put("/location/apps/:encodedSubject", async (context) => {
  const admin = await requireAdministrator(context); if (admin instanceof Response) return admin;
  const subject = context.req.param("encodedSubject");
  if (!(await locationApplications(context.env)).some((app) => app.subject === subject)) return context.json({ error: "애플리케이션을 찾을 수 없습니다." }, 404);
  const body = await context.req.json().catch(() => null) as Record<string, unknown> | null;
  const ids = await checkedPlaceIds(context.env, body);
  if (!ids?.length || !["observe", "enforce"].includes(body?.mode as string)) return context.json({ error: "장소 또는 모드가 올바르지 않습니다." }, 400);
  return auditStandaloneOperation(context.env, "location.app_rule.update", context.req.path, async () => {
    await context.env.DB.prepare("INSERT INTO location_app_rules (subject, place_ids, mode) VALUES (?, ?, ?) ON CONFLICT(subject) DO UPDATE SET place_ids = excluded.place_ids, mode = excluded.mode").bind(subject, JSON.stringify(ids), body!.mode).run();
    return { response: Response.json({ subject, placeIds: ids, mode: body!.mode }), actorUserId: admin.userId, targetUserId: null };
  });
});

locationAdminRoutes.delete("/location/apps/:encodedSubject", async (context) => {
  const admin = await requireAdministrator(context); if (admin instanceof Response) return admin;
  return auditStandaloneOperation(context.env, "location.app_rule.delete", context.req.path, async () => {
    await context.env.DB.prepare("DELETE FROM location_app_rules WHERE subject = ?").bind(context.req.param("encodedSubject")).run();
    return { response: Response.json({ deleted: true }), actorUserId: admin.userId, targetUserId: null };
  });
});

locationAdminRoutes.put("/location/policy", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const body = (await context.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body !== "object") return context.json({ error: "요청 형식이 올바르지 않습니다." }, 400);
  if (!["off", "observe", "enforce"].includes(body.mode as string)) return context.json({ error: "모드가 올바르지 않습니다." }, 400);
  if (!["network", "browser", "network_or_browser"].includes(body.signal as string)) return context.json({ error: "확인 방식이 올바르지 않습니다." }, 400);
  const margin = Math.round(Number(body.networkMarginKm));
  const accuracy = Math.round(Number(body.maxAccuracyM));
  if (!Number.isFinite(margin) || margin < 0 || margin > 500) return context.json({ error: "네트워크 허용 오차는 0km에서 500km 사이여야 합니다." }, 400);
  if (!Number.isFinite(accuracy) || accuracy < 20 || accuracy > 50_000) return context.json({ error: "브라우저 위치 정확도는 20m에서 50km 사이여야 합니다." }, 400);
  const exemptGroups = Array.isArray(body.exemptGroups) ? [...new Set((body.exemptGroups as unknown[]).filter((id): id is string => typeof id === "string" && id.length <= 128))].slice(0, 50) : [];
  if (exemptGroups.length) {
    const found = await context.env.DB.prepare(`SELECT id FROM directory_groups WHERE id IN (${exemptGroups.map(() => "?").join(",")})`).bind(...exemptGroups).all<{ id: string }>();
    if (found.results.length !== exemptGroups.length) return context.json({ error: "없는 그룹이 있습니다." }, 400);
  }
  const policy: LocationPolicy = { mode: body.mode as LocationMode, signal: body.signal as LocationSignal, networkMarginKm: margin, maxAccuracyM: accuracy, exemptGroups };

  // Never lock the person who is saving out of their own organization.
  if (policy.mode === "enforce") {
    if ((await listPlaces(context.env, true)).length === 0) return context.json({ error: "켜 둔 장소가 하나도 없습니다. 장소를 먼저 추가하세요." }, 409);
    const self = await evaluateLocation(context.env, { request: context.req.raw, userId: admin.userId, policy });
    if (!self.pass) {
      return context.json({
        error: "지금 이 접속은 허용된 장소 밖이라, 적용하면 관리자 본인도 로그인할 수 없게 됩니다. 허용된 장소 안에서 브라우저 위치를 확인하거나, 관리자 그룹을 예외로 지정한 뒤 다시 저장하세요.",
        code: self.needsBrowser ? "needs_browser" : "outside",
      }, 409);
    }
  }
  return auditStandaloneOperation(context.env, "location.policy.update", context.req.path, async () => {
    await saveLocationPolicy(context.env, policy, admin.userId);
    return { response: Response.json({ policy }), actorUserId: admin.userId, targetUserId: null };
  });
});

/** What a sign-in screen may know without an account: is a place check in force, and is this browser already cleared. */
locationPublicRoutes.get("/api/location/status", async (context) => {
  context.header("Cache-Control", "no-store");
  const policy = await loadLocationPolicy(context.env);
  const verdict = await evaluateLocation(context.env, { request: context.req.raw, userId: null });
  return context.json({ enforced: policy.mode === "enforce", satisfied: verdict.pass, canShareLocation: policy.signal !== "network" });
});

/** The browser reports where it is; inside a place, it gets a short-lived cookie that says so. */
locationPublicRoutes.post("/api/location/proof", async (context) => {
  context.header("Cache-Control", "no-store");
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) return context.json({ ok: false, reason: "unavailable" }, 403);
  const body = (await context.req.json().catch(() => null)) as { latitude?: unknown; longitude?: unknown; accuracy?: unknown } | null;
  const latitude = Number(body?.latitude);
  const longitude = Number(body?.longitude);
  const accuracy = Number(body?.accuracy);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude) || Math.abs(latitude) > 90 || Math.abs(longitude) > 180 || !Number.isFinite(accuracy) || accuracy < 0) {
    return context.json({ ok: false, reason: "unavailable" }, 400);
  }
  const result = await recordLocationProof(context.env, { request: context.req.raw, latitude, longitude, accuracyM: accuracy });
  if (!result.ok) return context.json({ ok: false, reason: result.reason }, result.reason === "rate_limited" ? 429 : 200);
  context.header("Set-Cookie", proofCookie(context.env, result.token));
  return context.json({ ok: true });
});
