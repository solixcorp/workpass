import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { notifySecurity } from "../../src/users/notifications";
import { recordLogin } from "../../src/users/login-history";
import { enforceLocationAfterPasskeyLogin } from "../../src/security/location-gate";
import { saveLocationPolicy, DEFAULT_LOCATION_POLICY } from "../../src/security/location-policy";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Security-7d9Kpw9zL2xQ";

describe("security notifications", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "security-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))) } as unknown as Env;
  const jar = new Map<string, string>();
  let userId = "";
  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string> }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET" && !headers.Origin) headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, { method: init?.method ?? "GET", headers,
      body: init?.body === undefined ? undefined : JSON.stringify(init.body) }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i > 0) { const value = pair.slice(i + 1); if (value) jar.set(pair.slice(0, i), value); else jar.delete(pair.slice(0, i)); }
    }
    return response;
  }
  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    const bootstrap = await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` }, body: { email: "admin@security.test", name: "Admin", username: "securityadmin", password: PASSWORD } });
    userId = ((await bootstrap.json()) as any).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "securityadmin", password: PASSWORD } })).status).toBe(200);
  });
  test("HOTP enrollment and removal notify the affected user", async () => {
    const response = await call("/api/mfa/hotp/enroll", { method: "POST", body: { label: "내 토큰" } });
    expect(response.status).toBe(201);
    const token = await response.json() as { tokenId: string };
    expect((await call(`/api/mfa/hotp/${token.tokenId}`, { method: "DELETE" })).status).toBe(200);
    const rows = await db.prepare("SELECT title, link FROM user_notifications WHERE user_id = ? AND kind = 'security_mfa' ORDER BY title").bind(userId).all<{ title: string; link: string }>();
    expect(rows.results.map((r) => r.title).sort()).toEqual(["2차 인증 수단이 등록되었습니다", "2차 인증 수단이 삭제되었습니다"].sort());
    expect(rows.results.every((r) => r.link === "/security")).toBe(true);
  });
  test("administrator actions notify the affected account, not the administrator", async () => {
    const created = await call("/api/admin/users", { method: "POST", body: { email: "target@security.test", name: "Target", sendEmail: false } });
    expect(created.status).toBe(201);
    const target = ((await created.json()) as any).user.id as string;
    for (const [path, body] of [
      ["set-user-password", { userId: target, newPassword: "Changed-7d9Kpw9zL2xQ" }],
      ["set-role", { userId: target, role: "admin" }],
      ["ban-user", { userId: target }],
      ["unban-user", { userId: target }],
      ["revoke-user-sessions", { userId: target }],
    ] as const) expect((await call(`/api/auth/admin/${path}`, { method: "POST", body })).status).toBe(200);
    expect((await call(`/api/security/trusted-devices/user/${target}`, { method: "DELETE" })).status).toBe(200);
    const attach = await call(`/api/admin/users/${target}/mfa/hotp`, { method: "POST", body: { label: "token", secretBase32: "JBSWY3DPEHPK3PXP" } });
    expect(attach.status).toBe(201);
    const token = ((await attach.json()) as any).token.id;
    expect((await call(`/api/admin/users/${target}/mfa/hotp/${token}`, { method: "DELETE" })).status).toBe(200);
    expect((await call(`/api/admin/users/${target}/mfa/reset`, { method: "POST" })).status).toBe(200);
    const rows = await db.prepare("SELECT kind, title FROM user_notifications WHERE user_id = ?").bind(target).all<{ kind: string; title: string }>();
    expect(rows.results.map((r) => r.title)).toEqual(expect.arrayContaining([
      "계정 역할이 변경되었습니다", "계정이 비활성화되었습니다", "계정이 활성화되었습니다", "모든 세션이 해제되었습니다", "신뢰 기기가 해제되었습니다",
      "2차 인증 수단이 등록되었습니다", "2차 인증 수단이 삭제되었습니다",
      "비밀번호가 변경되었습니다",
    ]));
  });
  test("security notices deduplicate by user, kind and title for 60 seconds", async () => {
    const notice = { kind: "security_account", title: "테스트", body: "알림", link: "/security" };
    await Promise.all([notifySecurity(env, userId, notice), notifySecurity(env, userId, notice)]);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE title = ?").bind(notice.title).first<{ n: number }>())?.n).toBe(1);
    await db.prepare("UPDATE user_notifications SET created_at = ? WHERE title = ?").bind(new Date(Date.now() - 61_000).toISOString(), notice.title).run();
    await notifySecurity(env, userId, notice);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE title = ?").bind(notice.title).first<{ n: number }>())?.n).toBe(2);
  });
  test("new device and country only alert after the first login", async () => {
    const request = (agent: string, country: string) => ({ headers: new Headers({ "user-agent": agent }), cf: { country } });
    await recordLogin(env, request("Macintosh Chrome/1", "KR"), userId, "password");
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE kind = 'security_new_device'").first<{ n: number }>())?.n).toBe(0);
    await recordLogin(env, request("Macintosh Chrome/2", "KR"), userId, "password");
    await recordLogin(env, request("Macintosh Chrome/2", "US"), userId, "password");
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE kind = 'security_new_device'").first<{ n: number }>())?.n).toBe(1);
  });
  test("passkey location check preserves or revokes the new session", async () => {
    const row = await db.prepare('SELECT token FROM "session" WHERE "userId" = ? LIMIT 1').bind(userId).first<{ token: string }>();
    expect(row).not.toBeNull();
    const issued = new Response(null, { headers: { "set-cookie": `better-auth.session_token=${row!.token}.signature; Path=/` } });
    const request = new Request(`${ORIGIN}/api/auth/passkey/verify-authentication`);
    const check = () => enforceLocationAfterPasskeyLogin(env, request, issued, userId, "/api/auth/passkey/verify-authentication");
    await db.prepare("INSERT INTO location_places (id, name, latitude, longitude, radius_m, enabled, created_by, created_at, updated_at) VALUES ('p', 'Office', 37, 127, 100, 1, ?, ?, ?)")
      .bind(userId, new Date().toISOString(), new Date().toISOString()).run();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "observe" }, userId);
    expect(await check()).toBeNull();
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(row!.token).first()).not.toBeNull();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "off" }, userId);
    expect(await check()).toBeNull();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "enforce" }, userId);
    const denied = await check();
    expect(denied?.status).toBe(403);
    expect(await denied?.json()).toMatchObject({ code: "location_denied" });
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(row!.token).first()).toBeNull();
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE kind = 'security_location'").first<{ n: number }>())?.n).toBe(1);
  });
  test("a notification storage failure never breaks the underlying action", async () => {
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "off" }, userId);
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "securityadmin", password: PASSWORD } })).status).toBe(200);
    await db.prepare("DROP TABLE user_notifications").run();
    expect((await call("/api/mfa/hotp/enroll", { method: "POST", body: { label: "다른 토큰" } })).status).toBe(201);
    expect(await recordLogin(env, { headers: new Headers({ "user-agent": "Linux Firefox/1" }), cf: { country: "GB" } }, userId, "password")).not.toBeNull();
    await notifySecurity(env, userId, { kind: "security_account", title: "테스트", body: "알림" });
  });
});
