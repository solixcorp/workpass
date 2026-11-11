/**
 * The administrator's view of one user: summary, groups, apps, devices,
 * authenticators and the profile. Reads are administrator-only; the profile
 * is the one thing an administrator can change here.
 */

import { Hono } from "hono";
import { createAuth } from "../auth/config";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { describeDevice } from "./device";
import { PROFILE_FIELDS, readProfile, validateProfile } from "./profile";

export const userDetailRoutes = new Hono<{ Bindings: Env }>();

userDetailRoutes.use("/users/:id/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

async function userRow(env: Env, id: string) {
  return env.DB.prepare(
    `SELECT id, name, email, username, role, banned, "emailVerified" AS emailVerified, "phoneNumber" AS phoneNumber,
            "phoneNumberVerified" AS phoneVerified, "twoFactorEnabled" AS twoFactor, "createdAt" AS createdAt
     FROM "user" WHERE id = ?`,
  ).bind(id).first<{
    id: string; name: string; email: string; username: string | null; role: string | null; banned: number | null;
    emailVerified: number | null; phoneNumber: string | null; phoneVerified: number | null; twoFactor: number | null; createdAt: unknown;
  }>();
}

const rows = async <T>(promise: Promise<{ results: T[] }>): Promise<T[]> => promise.then((r) => r.results).catch(() => []);

userDetailRoutes.get("/users/:id/detail", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const db = context.env.DB;
  const user = await userRow(context.env, context.req.param("id"));
  if (!user) return context.json({ error: "사용자를 찾을 수 없습니다." }, 404);
  const last = await db.prepare("SELECT occurred_at AS at FROM login_history WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 1")
    .bind(user.id).first<{ at: string }>().catch(() => null);
  const lockdown = await db.prepare("SELECT 1 AS n FROM account_lockdowns WHERE user_id = ? AND lifted_at IS NULL LIMIT 1")
    .bind(user.id).first().catch(() => null);
  const reports = await db.prepare("SELECT COUNT(*) AS n FROM suspicious_reports WHERE user_id = ? AND status = 'open'")
    .bind(user.id).first<{ n: number }>().catch(() => null);
  return context.json({
    user: {
      id: user.id, name: user.name, email: user.email, username: user.username,
      roles: (user.role ?? "user").split(",").filter(Boolean),
      active: !user.banned, lockedDown: lockdown !== null, emailVerified: user.emailVerified === 1,
      phoneNumber: user.phoneNumber, phoneVerified: user.phoneVerified === 1,
      twoFactorEnabled: user.twoFactor === 1, createdAt: user.createdAt, lastLoginAt: last?.at ?? null,
      openReports: reports?.n ?? 0,
    },
  });
});

userDetailRoutes.get("/users/:id/groups", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const groups = await rows(context.env.DB.prepare(
    `SELECT g.id, g.name, g.description FROM directory_group_members m
     JOIN directory_groups g ON g.id = m.group_id WHERE m.user_id = ? ORDER BY g.name ASC`,
  ).bind(id).all<{ id: string; name: string; description: string | null }>());
  return context.json({ groups });
});

/** Every app the user can open, and why: the whole organization or one of their groups. */
userDetailRoutes.get("/users/:id/applications", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const db = context.env.DB;
  const memberOf = new Map((await rows(db.prepare(
    "SELECT g.id, g.name FROM directory_group_members m JOIN directory_groups g ON g.id = m.group_id WHERE m.user_id = ?",
  ).bind(id).all<{ id: string; name: string }>())).map((g) => [g.id, g.name]));
  const apps = await rows(db.prepare(
    `SELECT slug, name, protocol, binding, enabled, icon_key AS iconKey, icon_url AS iconUrl, hide_from_dashboard AS hidden
     FROM applications ORDER BY name ASC LIMIT 300`,
  ).all<{ slug: string; name: string; protocol: string; binding: string | null; enabled: number; iconKey: string | null; iconUrl: string | null; hidden: number }>());
  const policyGroups = await rows(db.prepare("SELECT subject, group_id FROM app_policy_groups").all<{ subject: string; group_id: string }>());
  const bySubject = new Map<string, string[]>();
  for (const row of policyGroups) bySubject.set(row.subject, [...(bySubject.get(row.subject) ?? []), row.group_id]);
  const last = new Map((await rows(db.prepare(
    "SELECT subject, MAX(occurred_at) AS at FROM app_grant_events WHERE user_id = ? GROUP BY subject",
  ).bind(id).all<{ subject: string; at: string }>())).map((r) => [r.subject, r.at]));

  const result = apps.map((app) => {
    const required = bySubject.get(`app:${app.slug}`) ?? [];
    const matching = required.filter((groupId) => memberOf.has(groupId));
    const subject = app.binding ? `${app.protocol}:${app.binding}` : null;
    return {
      slug: app.slug, name: app.name, protocol: app.protocol, enabled: app.enabled === 1, hidden: app.hidden === 1,
      icon: app.iconKey ? `/application/${app.slug}/icon` : app.iconUrl,
      access: required.length === 0 ? "everyone" : matching.length > 0 ? "group" : "none",
      via: matching.map((groupId) => memberOf.get(groupId)!),
      lastSignInAt: subject ? last.get(subject) ?? null : null,
    };
  });
  return context.json({ applications: result });
});

userDetailRoutes.get("/users/:id/devices", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const db = context.env.DB;
  const currentSession = id === admin.userId ? await createAuth(context.env).api.getSession({ headers: context.req.raw.headers }) : null;
  const sessions = await rows(db.prepare(
    `SELECT id, "ipAddress" AS ip, "userAgent" AS userAgent, "createdAt" AS createdAt, "expiresAt" AS expiresAt
     FROM "session" WHERE "userId" = ? ORDER BY "createdAt" DESC LIMIT 50`,
  ).bind(id).all<{ id: string; ip: string | null; userAgent: string | null; createdAt: unknown; expiresAt: unknown }>());
  const trusted = await rows(db.prepare(
    `SELECT id, label, created_at AS createdAt, last_seen_at AS lastSeenAt, expires_at AS expiresAt, revoked_at AS revokedAt
     FROM trusted_devices WHERE user_id = ? ORDER BY last_seen_at DESC LIMIT 50`,
  ).bind(id).all<{ id: string; label: string; createdAt: string; lastSeenAt: string; expiresAt: string; revokedAt: string | null }>());
  const logins = await rows(db.prepare(
    `SELECT id, occurred_at AS at, ip, user_agent AS userAgent, country, region, city, method
     FROM login_history WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 100`,
  ).bind(id).all<{ id: string; at: string; ip: string | null; userAgent: string | null; country: string | null; region: string | null; city: string | null; method: string | null }>());
  const reports = await rows(db.prepare(
    "SELECT id, login_id AS loginId, created_at AS createdAt, status FROM suspicious_reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
  ).bind(id).all<{ id: string; loginId: string | null; createdAt: string; status: string }>());

  // One row per device (same OS and browser), newest sign-in first.
  const devices = new Map<string, { label: string; lastAt: string; location: string | null; ip: string | null; count: number }>();
  for (const login of logins) {
    const label = describeDevice(login.userAgent).label;
    const place = [login.city, login.region, login.country].filter(Boolean).join(", ") || null;
    const existing = devices.get(label);
    if (existing) existing.count += 1;
    else devices.set(label, { label, lastAt: login.at, location: place, ip: login.ip, count: 1 });
  }
  return context.json({
    devices: [...devices.values()],
    sessions: sessions.map((s) => ({ id: s.id, ip: s.ip, device: describeDevice(s.userAgent).label, createdAt: s.createdAt, expiresAt: s.expiresAt, current: s.id === currentSession?.session.id })),
    trusted,
    logins: logins.map((l) => ({
      id: l.id, at: l.at, ip: l.ip, device: describeDevice(l.userAgent).label, method: l.method,
      location: [l.city, l.region, l.country].filter(Boolean).join(", ") || null,
      reported: reports.some((r) => r.loginId === l.id),
    })),
    reports,
  });
});

userDetailRoutes.delete("/users/:id/sessions/:sessionId", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const userId = context.req.param("id");
  const sessionId = context.req.param("sessionId");
  const current = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  return auditStandaloneOperation(context.env, "identity.user.session_revoke.success_or_failure", context.req.path, async () => {
    const audit = { actorUserId: admin.userId, targetUserId: userId };
    const db = context.env.DB;
    const session = await db.prepare('SELECT token FROM "session" WHERE id = ? AND "userId" = ?').bind(sessionId, userId).first<{ token: string }>();
    if (!session) return { response: Response.json({ error: "세션을 찾을 수 없습니다." }, { status: 404 }), ...audit };
    if (admin.userId === userId && current?.session.id === sessionId) return { response: Response.json({ error: "지금 쓰는 세션은 종료할 수 없습니다. 로그아웃을 이용하세요." }, { status: 409 }), ...audit };
    const results = await db.batch([
      ...["session_mfa_proofs", "session_step_up_requirements", "session_network_bindings", "account_session_contexts"].map((table) => db.prepare(`DELETE FROM ${table} WHERE session_token = ? AND user_id = ?`).bind(session.token, userId)),
      db.prepare('DELETE FROM "session" WHERE id = ? AND "userId" = ? AND token = ?').bind(sessionId, userId, session.token),
    ]);
    if (!results[results.length - 1]?.meta.changes) return { response: Response.json({ error: "세션을 찾을 수 없습니다." }, { status: 404 }), ...audit };
    return { response: Response.json({ revoked: true }), ...audit };
  });
});

userDetailRoutes.get("/users/:id/authenticators", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const db = context.env.DB;
  const password = await db.prepare("SELECT updated_at AS at FROM opaque_credential_records WHERE user_id = ?")
    .bind(id).first<{ at: string }>().catch(() => null);
  const passkeys = await rows(db.prepare(
    `SELECT id, name, "createdAt" AS createdAt, "deviceType" AS deviceType FROM passkey WHERE "userId" = ? ORDER BY "createdAt" DESC LIMIT 20`,
  ).bind(id).all<{ id: string; name: string | null; createdAt: unknown; deviceType: string | null }>());
  const totp = await db.prepare(`SELECT verified FROM "twoFactor" WHERE "userId" = ? LIMIT 1`)
    .bind(id).first<{ verified: number | null }>().catch(() => null);
  const tokens = await rows(db.prepare(
    "SELECT id, label, created_at AS createdAt FROM mfa_hotp_tokens WHERE user_id = ? ORDER BY created_at ASC LIMIT 20",
  ).bind(id).all<{ id: string; label: string; createdAt: string }>());
  const user = await userRow(context.env, id);
  return context.json({
    password: { set: password !== null, changedAt: password?.at ?? null },
    passkeys,
    totp: totp !== null && totp.verified !== 0,
    otp: user?.twoFactor === 1,
    hardwareTokens: tokens,
  });
});

userDetailRoutes.get("/users/:id/profile", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const user = await userRow(context.env, id);
  if (!user) return context.json({ error: "사용자를 찾을 수 없습니다." }, 404);
  return context.json({
    login: user.username ?? user.email, name: user.name, email: user.email, phoneNumber: user.phoneNumber,
    fields: await readProfile(context.env, id),
    schema: PROFILE_FIELDS,
  });
});

userDetailRoutes.put("/users/:id/profile", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const user = await userRow(context.env, id);
  if (!user) return context.json({ error: "사용자를 찾을 수 없습니다." }, 404);
  const body = await context.req.json().catch(() => null);
  const checked = validateProfile(body);
  if ("error" in checked) return context.json({ error: checked.error }, 400);
  return auditStandaloneOperation(context.env, "identity.user.profile_update", context.req.path, async () => {
    const db = context.env.DB;
    if (checked.name !== undefined) await db.prepare('UPDATE "user" SET name = ?, "updatedAt" = ? WHERE id = ?').bind(checked.name, new Date().toISOString(), id).run();
    if (checked.phoneNumber !== undefined) {
      try {
        await db.prepare('UPDATE "user" SET "phoneNumber" = ?, "phoneNumberVerified" = 0, "updatedAt" = ? WHERE id = ?')
          .bind(checked.phoneNumber, new Date().toISOString(), id).run();
      } catch {
        return { response: Response.json({ error: "이 번호는 쓸 수 없습니다." }, { status: 409 }), actorUserId: admin.userId, targetUserId: id };
      }
    }
    if (checked.fields) {
      const merged = { ...(await readProfile(context.env, id)), ...checked.fields };
      for (const key of Object.keys(merged)) if (!merged[key]) delete merged[key];
      await db.prepare(
        `INSERT INTO user_profiles (user_id, data, updated_by, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (user_id) DO UPDATE SET data = excluded.data, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
      ).bind(id, JSON.stringify(merged), admin.userId, new Date().toISOString()).run();
    }
    return { response: Response.json({ saved: true }), actorUserId: admin.userId, targetUserId: id };
  });
});
