/**
 * What a signed-in person sees about themselves: notifications, their profile
 * and phone number, recent sign-ins with security events, reports of
 * activity they do not recognise, and requests for an app they cannot open.
 */

import { Hono } from "hono";
import { createAuth } from "../auth/config";
import { auditStandaloneOperation } from "../audit/store";
import type { Env } from "../env";
import { describeDevice } from "./device";
import { notifyAdmins, notifyUser } from "./notifications";
import { sendPhoneCode, verifyPhoneCode } from "./phone-verification";
import { smsAvailable } from "../sms/provider";
import { validateProfile } from "./profile";

export const meRoutes = new Hono<{ Bindings: Env }>();

meRoutes.use("/api/me/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

type Me = { userId: string; name: string; email: string };

async function requireMe(context: { env: Env; req: { raw: { headers: Headers }; method: string; header: (name: string) => string | undefined } }): Promise<Me | Response> {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return Response.json({ error: "로그인이 필요합니다." }, { status: 401 });
  if (context.req.method !== "GET" && context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) {
    return Response.json({ error: "요청을 처리할 수 없습니다." }, { status: 403 });
  }
  return { userId: session.user.id, name: session.user.name, email: session.user.email };
}

const rows = async <T>(promise: Promise<{ results: T[] }>): Promise<T[]> => promise.then((r) => r.results).catch(() => []);

meRoutes.get("/api/me/notifications", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const notifications = await rows(context.env.DB.prepare(
    `SELECT id, kind, title, body, link, created_at AS createdAt, read_at AS readAt
     FROM user_notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
  ).bind(me.userId).all<{ id: string; kind: string; title: string; body: string; link: string | null; createdAt: string; readAt: string | null }>());
  return context.json({ notifications, unread: notifications.filter((n) => !n.readAt).length });
});

/** Mark some notifications (or all) as read. */
meRoutes.post("/api/me/notifications/read", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const body = (await context.req.json().catch(() => null)) as { ids?: unknown } | null;
  const now = new Date().toISOString();
  if (Array.isArray(body?.ids) && body!.ids.length > 0) {
    const ids = (body!.ids as unknown[]).filter((id): id is string => typeof id === "string").slice(0, 50);
    if (ids.length > 0) {
      await context.env.DB.prepare(
        `UPDATE user_notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL AND id IN (${ids.map(() => "?").join(",")})`,
      ).bind(now, me.userId, ...ids).run().catch(() => null);
    }
  } else {
    await context.env.DB.prepare("UPDATE user_notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL")
      .bind(now, me.userId).run().catch(() => null);
  }
  return context.json({ ok: true });
});

meRoutes.get("/api/me/profile", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const user = await context.env.DB.prepare(
    `SELECT name, email, username, "phoneNumber" AS phoneNumber, "phoneNumberVerified" AS phoneVerified, "twoFactorEnabled" AS twoFactor FROM "user" WHERE id = ?`,
  ).bind(me.userId).first<{ name: string; email: string; username: string | null; phoneNumber: string | null; phoneVerified: number | null; twoFactor: number | null }>();
  if (!user) return context.json({ error: "사용자를 찾을 수 없습니다." }, 404);
  const profile = await context.env.DB.prepare("SELECT data FROM user_profiles WHERE user_id = ?").bind(me.userId).first<{ data: string }>().catch(() => null);
  let fields: Record<string, string> = {};
  try { fields = profile ? (JSON.parse(profile.data) as Record<string, string>) : {}; } catch { /* unreadable: show none */ }
  return context.json({
    name: user.name, email: user.email, login: user.username ?? user.email,
    phoneNumber: user.phoneNumber, phoneVerified: user.phoneVerified === 1, smsAvailable: smsAvailable(context.env), twoFactorEnabled: user.twoFactor === 1,
    // What the administrator keeps about this person, read-only here.
    fields: { title: fields.title ?? null, department: fields.department ?? null, organization: fields.organization ?? null, manager: fields.manager ?? null },
  });
});

/** A person may change their own name and phone number; the number is unverified until it is proven. */
meRoutes.put("/api/me/profile", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const body = (await context.req.json().catch(() => null)) as Record<string, unknown> | null;
  const checked = validateProfile({ name: body?.name, phoneNumber: body?.phoneNumber });
  if ("error" in checked) return context.json({ error: checked.error }, 400);
  return auditStandaloneOperation(context.env, "identity.user.self_profile_update", context.req.path, async () => {
    const db = context.env.DB;
    const now = new Date().toISOString();
    if (checked.name !== undefined) await db.prepare('UPDATE "user" SET name = ?, "updatedAt" = ? WHERE id = ?').bind(checked.name, now, me.userId).run();
    if (checked.phoneNumber !== undefined) {
      const current = await db.prepare('SELECT "phoneNumber" AS phoneNumber FROM "user" WHERE id = ?').bind(me.userId).first<{ phoneNumber: string | null }>();
      if ((current?.phoneNumber ?? null) !== checked.phoneNumber) {
        try {
          await db.prepare('UPDATE "user" SET "phoneNumber" = ?, "phoneNumberVerified" = 0, "updatedAt" = ? WHERE id = ?').bind(checked.phoneNumber, now, me.userId).run();
        } catch {
          return { response: Response.json({ error: "이 번호는 쓸 수 없습니다." }, { status: 409 }), actorUserId: me.userId, targetUserId: me.userId };
        }
      }
    }
    return { response: Response.json({ saved: true }), actorUserId: me.userId, targetUserId: me.userId };
  });
});

/** Send a code to the number saved on the account. */
meRoutes.post("/api/me/phone/send-code", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  return auditStandaloneOperation(context.env, "identity.user.phone_code_sent", context.req.path, async () => {
    const outcome = await sendPhoneCode(context.env, me.userId);
    const audit = { actorUserId: me.userId, targetUserId: me.userId };
    if (outcome.ok) return { response: Response.json({ sent: true, expiresInSeconds: outcome.expiresInSeconds }), ...audit };
    const message = {
      no_number: "먼저 휴대전화 번호를 저장하세요.",
      already_verified: "이미 확인된 번호입니다.",
      unavailable: "문자 발송이 설정되어 있지 않습니다. 관리자에게 문의하세요.",
      too_soon: `잠시 후 다시 요청하세요. (${(outcome as { retryAfterSeconds?: number }).retryAfterSeconds ?? 60}초 뒤)`,
      too_many: "코드를 너무 많이 요청했습니다. 한 시간 뒤에 다시 시도하세요.",
      delivery_failed: "문자를 보내지 못했습니다. 번호를 확인하거나 잠시 후 다시 시도하세요.",
    }[outcome.reason];
    const status = outcome.reason === "too_soon" || outcome.reason === "too_many" ? 429 : outcome.reason === "delivery_failed" ? 502 : 409;
    return { response: Response.json({ error: message, reason: outcome.reason, ...(outcome.reason === "too_soon" ? { retryAfterSeconds: outcome.retryAfterSeconds } : {}) }, { status }), ...audit };
  });
});

/** Check the code; a right one marks the number verified. */
meRoutes.post("/api/me/phone/verify", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const body = (await context.req.json().catch(() => null)) as { code?: unknown } | null;
  const code = typeof body?.code === "string" ? body.code.trim() : "";
  return auditStandaloneOperation(context.env, "identity.user.phone_verify", context.req.path, async () => {
    const outcome = await verifyPhoneCode(context.env, me.userId, code);
    const audit = { actorUserId: me.userId, targetUserId: me.userId };
    if (outcome.ok) {
      await notifyUser(context.env, me.userId, { kind: "phone_verified", title: "휴대전화 번호를 확인했습니다", body: "이 번호로 2차 인증 코드를 받을 수 있습니다.", link: "/me" });
      return { response: Response.json({ verified: true }), ...audit };
    }
    const message = {
      no_code: "인증 코드를 먼저 요청하세요.",
      expired: "코드가 만료되었습니다. 새 코드를 요청하세요.",
      wrong: "코드가 맞지 않습니다.",
      too_many_attempts: "시도 횟수를 넘었습니다. 새 코드를 요청하세요.",
    }[outcome.reason];
    return { response: Response.json({ error: message, reason: outcome.reason, ...(outcome.reason === "wrong" ? { attemptsLeft: outcome.attemptsLeft } : {}) }, { status: outcome.reason === "too_many_attempts" ? 429 : 400 }), ...audit };
  });
});

/** Audit event types a person should see about their own account. */
const SECURITY_EVENTS = [
  "identity.user.password_%", "identity.user.activation.completed", "identity.user.account_recovery", "identity.user.recovery_link.issued",
  "identity.user.sessions_revoke%", "identity.user.lockdown%", "identity.user.trusted_devices.revoke", "identity.user.role_change%",
  "authentication.passkey.registration%", "authentication.session.location_violation", "mfa.%", "opaque.register.finish",
];

meRoutes.get("/api/me/activity", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const db = context.env.DB;
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const logins = await rows(db.prepare(
    `SELECT id, occurred_at AS at, ip, user_agent AS userAgent, country, region, city, method
     FROM login_history WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 200`,
  ).bind(me.userId).all<{ id: string; at: string; ip: string | null; userAgent: string | null; country: string | null; region: string | null; city: string | null; method: string | null }>());
  const reported = new Set((await rows(db.prepare("SELECT login_id AS loginId FROM suspicious_reports WHERE user_id = ? AND login_id IS NOT NULL").bind(me.userId).all<{ loginId: string }>())).map((r) => r.loginId));

  // One row per device and place: when it last signed in, how many times.
  const groups = new Map<string, { loginId: string; device: string; os: string; lastAt: string; location: string | null; ip: string | null; count: number; reported: boolean }>();
  for (const login of logins) {
    const device = describeDevice(login.userAgent);
    const place = [login.city, login.region, login.country].filter(Boolean).join(", ") || null;
    const key = `${device.label}|${place ?? login.ip ?? ""}`;
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
      existing.reported ||= reported.has(login.id);
    } else {
      groups.set(key, { loginId: login.id, device: device.label, os: device.os, lastAt: login.at, location: place, ip: login.ip, count: 1, reported: reported.has(login.id) });
    }
  }

  const likes = SECURITY_EVENTS.map(() => "event_type LIKE ?").join(" OR ");
  const events = await rows(db.prepare(
    `SELECT id, occurred_at AS at, event_type AS type, outcome, actor_user_id AS actorId, target_user_id AS targetId
     FROM audit_events WHERE (actor_user_id = ? OR target_user_id = ?) AND occurred_at >= ? AND outcome != 'started' AND (${likes})
     ORDER BY occurred_at DESC LIMIT 30`,
  ).bind(me.userId, me.userId, since, ...SECURITY_EVENTS).all<{ id: string; at: string; type: string; outcome: string; actorId: string | null; targetId: string | null }>());

  return context.json({
    logins: [...groups.values()].slice(0, 20),
    events: events.map((event) => ({ id: event.id, at: event.at, type: event.type, outcome: event.outcome, byAdministrator: event.actorId !== null && event.actorId !== me.userId })),
  });
});

/** "I do not recognise this sign-in." */
meRoutes.post("/api/me/suspicious-reports", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const body = (await context.req.json().catch(() => null)) as { loginId?: unknown; summary?: unknown } | null;
  const summary = typeof body?.summary === "string" ? body.summary.trim().slice(0, 500) : "";
  const loginId = typeof body?.loginId === "string" ? body.loginId.slice(0, 64) : null;
  const db = context.env.DB;
  let where = "";
  if (loginId) {
    const mine = await db.prepare("SELECT ip, user_agent AS userAgent, city, country, occurred_at AS at FROM login_history WHERE id = ? AND user_id = ?")
      .bind(loginId, me.userId).first<{ ip: string | null; userAgent: string | null; city: string | null; country: string | null; at: string }>().catch(() => null);
    if (!mine) return context.json({ error: "그 로그인 기록을 찾을 수 없습니다." }, 404);
    where = `${describeDevice(mine.userAgent).label}, ${[mine.city, mine.country].filter(Boolean).join(", ") || mine.ip || "위치 알 수 없음"}`;
  }
  const open = await db.prepare("SELECT 1 AS n FROM suspicious_reports WHERE user_id = ? AND status = 'open' AND COALESCE(login_id, '') = ?")
    .bind(me.userId, loginId ?? "").first().catch(() => null);
  if (open) return context.json({ error: "이미 신고했고 관리자가 확인 중입니다." }, 409);
  const id = crypto.randomUUID();
  return auditStandaloneOperation(context.env, "security.suspicious_report", context.req.path, async () => {
    await db.prepare("INSERT INTO suspicious_reports (id, user_id, login_id, summary, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(id, me.userId, loginId, [where, summary].filter(Boolean).join(" · ") || "의심스러운 활동", new Date().toISOString()).run();
    await notifyAdmins(context.env, {
      kind: "suspicious_report", title: "의심스러운 활동 신고",
      body: `${me.name}(${me.email})님이 로그인을 의심스럽다고 신고했습니다.${where ? ` ${where}` : ""}`,
      link: `/admin/users/${me.userId}`,
    });
    return { response: Response.json({ id }, { status: 201 }), actorUserId: me.userId, targetUserId: me.userId };
  });
});

/** Ask the administrators for an app the person cannot open; `slug` is optional. */
meRoutes.post("/api/me/app-requests", async (context) => {
  const me = await requireMe(context);
  if (me instanceof Response) return me;
  const body = (await context.req.json().catch(() => null)) as { slug?: unknown; message?: unknown } | null;
  const slug = typeof body?.slug === "string" ? body.slug : "";
  const message = typeof body?.message === "string" ? body.message.trim().slice(0, 500) : "";
  if (!message) return context.json({ error: "관리자에게 보낼 내용을 적어 주세요." }, 400);
  // The app is optional: a person may not know what it is called in this system.
  let appName: string | null = null;
  if (slug) {
    const app = await context.env.DB.prepare("SELECT name FROM applications WHERE slug = ?").bind(slug).first<{ name: string }>().catch(() => null);
    if (!app) return context.json({ error: "앱을 찾을 수 없습니다." }, 404);
    appName = app.name;
  }
  return auditStandaloneOperation(context.env, "app.access_request_message", context.req.path, async () => {
    await notifyAdmins(context.env, {
      kind: "app_request", title: appName ? `앱 접근 요청: ${appName}` : "앱 접근 요청",
      body: `${me.name}(${me.email}): ${message}`, link: `/admin/users/${me.userId}`,
    });
    return { response: Response.json({ sent: true }, { status: 201 }), actorUserId: me.userId, targetUserId: slug || null };
  });
});
