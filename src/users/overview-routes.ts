/** The administrator's overview: counts, service status, things to do, recent changes and security signals. */

import { Hono } from "hono";
import { transactionEmailAvailable } from "../mail/send";
import { auditStandaloneOperation } from "../audit/store";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { fingerprintMode } from "../security/fingerprint";
import { smsAvailable } from "../sms/provider";
import { notifyUser } from "./notifications";

export const overviewRoutes = new Hono<{ Bindings: Env }>();

async function count(env: Env, sql: string, ...values: unknown[]): Promise<number> {
  const row = await env.DB.prepare(sql).bind(...values).first<{ n: number }>().catch(() => null);
  return row?.n ?? 0;
}

/** Event types that are changes to the organization, not sign-ins. */
const CHANGE_TYPES = ["app.%", "directory.%", "policy.%", "access.policy.%", "oauth.client.%", "saml.%", "wsfed.%", "identity.user.create%", "identity.user.role_change%", "identity.user.disable%", "identity.user.enable%", "admin.setting.%", "attributes.%"];

overviewRoutes.get("/overview", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  context.header("Cache-Control", "no-store");
  const env = context.env;
  const day = 24 * 60 * 60 * 1000;
  const since = new Date(Date.now() - 30 * day).toISOString();

  const [users, activeUsers, groups, apps, enabledApps, pendingRequests, openReports, noPassword, protectedUsers] = await Promise.all([
    count(env, 'SELECT COUNT(*) AS n FROM "user"'),
    count(env, 'SELECT COUNT(*) AS n FROM "user" WHERE banned IS NULL OR banned = 0'),
    count(env, "SELECT COUNT(*) AS n FROM directory_groups"),
    count(env, "SELECT COUNT(*) AS n FROM applications"),
    count(env, "SELECT COUNT(*) AS n FROM applications WHERE enabled = 1"),
    count(env, "SELECT COUNT(*) AS n FROM access_requests WHERE status = 'pending'"),
    count(env, "SELECT COUNT(*) AS n FROM suspicious_reports WHERE status = 'open'"),
    count(env, `SELECT COUNT(*) AS n FROM "user" u WHERE (u.banned IS NULL OR u.banned = 0) AND NOT EXISTS (SELECT 1 FROM opaque_credential_records o WHERE o.user_id = u.id)`),
    count(env, `SELECT COUNT(*) AS n FROM "user" u WHERE (u.banned IS NULL OR u.banned = 0) AND (u."twoFactorEnabled" = 1 OR EXISTS (SELECT 1 FROM passkey p WHERE p."userId" = u.id) OR EXISTS (SELECT 1 FROM mfa_hotp_tokens t WHERE t.user_id = u.id))`),
  ]);

  const [failedSignIns, riskStepUps, riskDenied, locationViolations, lockdowns] = await Promise.all([
    count(env, "SELECT COUNT(*) AS n FROM audit_events WHERE occurred_at >= ? AND outcome = 'failure' AND event_type LIKE 'authentication.%'", since),
    count(env, "SELECT COUNT(*) AS n FROM audit_events WHERE occurred_at >= ? AND event_type = 'authentication.fingerprint.risk_step_up'", since),
    count(env, "SELECT COUNT(*) AS n FROM audit_events WHERE occurred_at >= ? AND event_type = 'authentication.fingerprint.risk_deny'", since),
    count(env, "SELECT COUNT(*) AS n FROM audit_events WHERE occurred_at >= ? AND event_type = 'authentication.session.location_violation'", since),
    count(env, "SELECT COUNT(*) AS n FROM audit_events WHERE occurred_at >= ? AND event_type = 'identity.user.lockdown'", since),
  ]);

  const likes = CHANGE_TYPES.map(() => "event_type LIKE ?").join(" OR ");
  const changes = await env.DB.prepare(
    `SELECT id, occurred_at AS at, event_type AS type, outcome, actor_user_id AS actorId, target_user_id AS targetId
     FROM audit_events WHERE outcome != 'started' AND (${likes}) ORDER BY occurred_at DESC LIMIT 8`,
  ).bind(...CHANGE_TYPES).all<{ id: string; at: string; type: string; outcome: string; actorId: string | null; targetId: string | null }>().then((r) => r.results).catch(() => []);
  const actorIds = [...new Set(changes.map((c) => c.actorId).filter((id): id is string => Boolean(id)))];
  const names = new Map<string, string>();
  if (actorIds.length) {
    const found = await env.DB.prepare(`SELECT id, name FROM "user" WHERE id IN (${actorIds.map(() => "?").join(",")})`).bind(...actorIds).all<{ id: string; name: string }>().catch(() => ({ results: [] as Array<{ id: string; name: string }> }));
    for (const row of found.results) names.set(row.id, row.name);
  }

  const tasks: Array<{ id: string; title: string; count: number; to: string; severity: "high" | "normal" }> = [];
  if (openReports > 0) tasks.push({ id: "reports", title: "사용자가 신고한 의심스러운 활동", count: openReports, to: "/admin/reports", severity: "high" });
  if (pendingRequests > 0) tasks.push({ id: "requests", title: "승인을 기다리는 접근 요청", count: pendingRequests, to: "/admin/access-requests", severity: "normal" });
  if (noPassword > 0) tasks.push({ id: "passwords", title: "아직 비밀번호를 설정하지 않은 사용자", count: noPassword, to: "/admin/users", severity: "normal" });

  const fingerprint = fingerprintMode(env);
  return context.json({
    counts: { users, activeUsers, groups, apps, enabledApps },
    services: [
      { name: "인증 서버와 데이터베이스", state: "ok", note: "응답 중" },
      { name: "메일 발송", state: transactionEmailAvailable(env) ? "ok" : "off", note: transactionEmailAvailable(env) ? "설정됨" : "설정하지 않음" },
      { name: "문자(SMS) 코드", state: smsAvailable(env) ? "ok" : "off", note: smsAvailable(env) ? "설정됨" : "설정하지 않음" },
      { name: "기기 위험 판정", state: fingerprint === "disabled" ? "off" : "ok", note: fingerprint === "disabled" ? "꺼짐" : "적용 중" },
    ],
    tasks,
    changes: changes.map((c) => ({ id: c.id, at: c.at, type: c.type, outcome: c.outcome, actor: c.actorId ? names.get(c.actorId) ?? null : null })),
    security: {
      windowDays: 30,
      protectedUsers, activeUsers,
      threats: { failedSignIns, riskStepUps, riskDenied, locationViolations, lockdowns },
      openReports,
    },
  });
});

overviewRoutes.get("/suspicious-reports", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  context.header("Cache-Control", "no-store");
  const status = new URL(context.req.url).searchParams.get("status") === "closed" ? "closed" : "open";
  const reports = await context.env.DB.prepare(
    `SELECT r.id, r.user_id AS userId, u.name, u.email, r.summary, r.created_at AS createdAt, r.status, r.handled_at AS handledAt
     FROM suspicious_reports r LEFT JOIN "user" u ON u.id = r.user_id WHERE r.status = ? ORDER BY r.created_at DESC LIMIT 100`,
  ).bind(status).all().then((r) => r.results).catch(() => []);
  return context.json({ reports });
});

overviewRoutes.post("/suspicious-reports/:id/close", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const report = await context.env.DB.prepare("SELECT user_id AS userId, status FROM suspicious_reports WHERE id = ?").bind(id).first<{ userId: string; status: string }>().catch(() => null);
  if (!report) return context.json({ error: "신고를 찾을 수 없습니다." }, 404);
  return auditStandaloneOperation(context.env, "security.suspicious_report_close", context.req.path, async () => {
    await context.env.DB.prepare("UPDATE suspicious_reports SET status = 'closed', handled_by = ?, handled_at = ? WHERE id = ? AND status = 'open'")
      .bind(admin.userId, new Date().toISOString(), id).run();
    await notifyUser(context.env, report.userId, { kind: "report_closed", title: "신고를 확인했습니다", body: "관리자가 신고하신 의심스러운 활동을 확인했습니다.", link: "/activity" });
    return { response: Response.json({ closed: true }), actorUserId: admin.userId, targetUserId: report.userId };
  });
});
