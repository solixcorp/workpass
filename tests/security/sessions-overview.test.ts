import { expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

test("session overview is private and enriches active sessions from matching login history", async () => {
  const { db } = createTestD1();
  const origin = "http://127.0.0.1:8787";
  const env = {
    DB: db, AUTH_SECRET: "overview-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  async function call(path: string, method = "GET", body?: unknown, extra: Record<string, string> = {}) {
    const headers: Record<string, string> = { ...extra };
    if (jar.size) headers.Cookie = [...jar].map(([key, value]) => `${key}=${value}`).join("; ");
    if (method !== "GET") headers.Origin = origin;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await worker.fetch(new Request(origin + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const index = pair.indexOf("=");
      if (index > 0) jar.set(pair.slice(0, index), pair.slice(index + 1));
    }
    return response;
  }
  expect((await call("/_internal/migrate", "POST", undefined, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
  const bootstrap = await call("/api/admin/bootstrap", "POST", {
    email: "admin@overview.test", name: "Admin", username: "overviewadmin", password: "Detail-7d9Kpw9zL2xQ",
  }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` });
  const userId = ((await bootstrap.json()) as { user: { id: string } }).user.id;
  const unauthorized = await call("/api/security/sessions/overview");
  expect(unauthorized.status).toBe(401);
  expect(unauthorized.headers.get("Cache-Control")).toBe("no-store");
  const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0";
  expect((await call("/api/auth/sign-in/username", "POST", {
    username: "overviewadmin", password: "Detail-7d9Kpw9zL2xQ",
  }, { "User-Agent": ua, "CF-Connecting-IP": "192.0.2.10" })).status).toBe(200);
  const current = await db.prepare('SELECT id FROM "session" WHERE "userId" = ?').bind(userId).first<{ id: string }>();
  await db.prepare('UPDATE "session" SET "ipAddress" = ?, "userAgent" = ? WHERE id = ?')
    .bind("192.0.2.10", ua, current!.id).run();
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "session" (id, "expiresAt", token, "createdAt", "updatedAt", "userId", "ipAddress") VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind("rotated", new Date(Date.now() + 86400000).toISOString(), "rotated-token", now, now, userId, "192.0.2.10").run();
  await db.prepare('INSERT INTO "session" (id, "expiresAt", token, "createdAt", "updatedAt", "userId", "ipAddress") VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind("unmatched", new Date(Date.now() + 86400000).toISOString(), "unmatched-token", now, now, userId, "192.0.2.99").run();
  await db.prepare(`INSERT INTO login_history (id, user_id, occurred_at, ip, user_agent, city, region, country)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind("matching", userId, "2099-01-01T00:00:00.000Z", "192.0.2.10", ua, "Seoul", "Seoul", "KR").run();
  await db.prepare(`INSERT INTO login_history (id, user_id, occurred_at, ip, user_agent, city, region, country)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind("newer", userId, "2099-01-02T00:00:00.000Z", "192.0.2.10", "Firefox/120 Linux", "Busan", null, "KR").run();
  const response = await call("/api/security/sessions/overview");
  expect(response.status).toBe(200);
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  const { sessions } = await response.json() as { sessions: Array<Record<string, any>> };
  const active = sessions.find((s) => s.current)!;
  expect(active).toMatchObject({ id: current!.id, userAgent: ua, ipAddress: "192.0.2.10", label: "Mac OS X Chrome", location: { city: "Seoul", region: "Seoul", country: "KR" } });
  expect(typeof active.token).toBe("string");
  expect(typeof active.updatedAt).toBe("string");
  expect(sessions.find((s) => s.id === "rotated")).toMatchObject({ current: false, token: "rotated-token", userAgent: null, label: "Linux Firefox", location: { city: "Busan", region: null, country: "KR" } });
  expect(sessions.find((s) => s.id === "unmatched")!.location).toBeNull();
});
