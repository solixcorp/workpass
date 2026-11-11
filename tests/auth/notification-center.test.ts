import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** Notifications, the person's own page, suspicious reports and the overview. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "SelfSvc-7d9Kpw9zL2xQ";

describe("self service and overview", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "detail-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string> }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET" && !headers.Origin) headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers, redirect: "manual",
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i <= 0) continue;
      const value = pair.slice(i + 1);
      if (value === "") jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), value);
    }
    return response;
  }
  const json = async (response: Response) => (await response.json()) as any;

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@self.test", name: "Admin", username: "selfadmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "selfadmin", password: PASSWORD } })).status).toBe(200);
  });

  test("pagination, category filters and legacy bell", async () => {
    for (let i = 0; i < 55; i++) await db.prepare("INSERT INTO user_notifications (id, user_id, kind, title, body, created_at, read_at) VALUES (?, ?, ?, 't', 'b', ?, ?)")
      .bind(`n${i}`, adminId, i % 2 ? 'app_assigned' : 'security_account', new Date(1700000000000 + i * 1000).toISOString(), i % 3 ? null : 'read').run();
    const bell = await json(await call('/api/me/notifications'));
    expect(bell.notifications).toHaveLength(50);
    expect(bell.unread).toBe(bell.notifications.filter((n: any) => !n.readAt).length);
    expect(bell.total).toBeUndefined();
    const page = await json(await call('/api/me/notifications?page=2&limit=10&unread=1&category=apps'));
    expect(page).toMatchObject({ page: 2, limit: 10, total: 18, unread: 36 });
    expect(page.notifications.every((n: any) => n.category === 'apps' && !n.readAt)).toBe(true);
    expect((await call('/api/me/notifications?page=0')).status).toBe(400);
    expect((await call('/api/me/notifications?page=1&category=other')).status).toBe(400);
  });
  test('preferences enforce opt-outs but never security', async () => {
    const prefs = await json(await call('/api/me/notification-preferences'));
    expect(prefs.categories.map((c: any) => [c.id, c.enabled, c.locked])).toEqual([['security', true, true], ['apps', true, false], ['requests', true, false]]);
    expect((await call('/api/me/notification-preferences', { method: 'PUT', body: { categories: { security: false } } })).status).toBe(400);
    expect((await call('/api/me/notification-preferences', { method: 'PUT', body: { categories: { other: false } } })).status).toBe(400);
    expect((await call('/api/me/notification-preferences', { method: 'PUT', body: { categories: { apps: false } } })).status).toBe(200);
    const { notifyUser, notifyUsers } = await import('../../src/users/notifications');
    await notifyUsers(env, [adminId, adminId], { kind: 'app_assigned', title: 'blocked', body: 'x' });
    await notifyUser(env, adminId, { kind: 'security_location', title: 'allowed', body: 'x' });
    expect(await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE title = 'blocked'").first()).toEqual({ n: 0 });
    expect(await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE title = 'allowed'").first()).toEqual({ n: 1 });
  });
  test('delete one and read only', async () => {
    expect((await call('/api/me/notifications/n0', { method: 'DELETE' })).status).toBe(200);
    expect((await call('/api/me/notifications/n0', { method: 'DELETE' })).status).toBe(404);
    expect((await call('/api/me/notifications', { method: 'DELETE' })).status).toBe(400);
    expect((await json(await call('/api/me/notifications?read=1', { method: 'DELETE' }))).deleted).toBe(18);
    expect((await json(await call('/api/me/notifications?page=1&unread=1'))).total).toBe(37);
    jar.clear();
    expect((await call('/api/me/notifications?page=1')).status).toBe(401);
  });
});
