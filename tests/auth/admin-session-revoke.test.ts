import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** The administrator's detail view of one user. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Detail-7d9Kpw9zL2xQ";

describe("user detail", () => {
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
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
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
      body: { email: "admin@detail.test", name: "Admin", username: "detadmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "detadmin", password: PASSWORD } })).status).toBe(200);
  });

  test('refuses current and wrong owner; revokes another session and its state', async () => {
    const otherId = (await json(await call('/api/admin/users', { method: 'POST', body: { email: 'other@detail.test', name: 'Other', sendEmail: false } }))).user.id;
    const self = await json(await call(`/api/admin/users/${adminId}/devices`));
    const current = self.sessions.find((s: any) => s.current);
    expect(current).toBeDefined();
    expect((await call(`/api/admin/users/${adminId}/sessions/${current.id}`, { method: 'DELETE' })).status).toBe(409);
    const now = new Date().toISOString();
    await db.prepare('INSERT INTO "session" (id, "expiresAt", token, "createdAt", "updatedAt", "userId") VALUES (?, ?, ?, ?, ?, ?)')
      .bind('other-session', new Date(Date.now() + 86400000).toISOString(), 'other-token', now, now, otherId).run();
    await db.prepare('INSERT INTO session_mfa_proofs (session_token, user_id, verified_at) VALUES (?, ?, ?)').bind('other-token', otherId, now).run();
    await db.prepare('INSERT INTO session_step_up_requirements (session_token, user_id, reasons, request_path, created_at, challenge_expires_at) VALUES (?, ?, ?, ?, ?, ?)').bind('other-token', otherId, '[]', '/', now, now).run();
    expect((await json(await call(`/api/admin/users/${otherId}/devices`))).sessions[0].current).toBe(false);
    expect((await call(`/api/admin/users/${adminId}/sessions/other-session`, { method: 'DELETE' })).status).toBe(404);
    expect(await json(await call(`/api/admin/users/${otherId}/sessions/other-session`, { method: 'DELETE' }))).toEqual({ revoked: true });
    expect(await db.prepare('SELECT * FROM session_mfa_proofs WHERE session_token = ?').bind('other-token').first()).toBeNull();
    expect(await db.prepare('SELECT * FROM session_step_up_requirements WHERE session_token = ?').bind('other-token').first()).toBeNull();
    expect(await db.prepare("SELECT kind FROM user_notifications WHERE user_id = ? AND kind = 'security_account'").bind(otherId).first()).toEqual({ kind: 'security_account' });
    expect((await call(`/api/admin/users/${otherId}/sessions/other-session`, { method: 'DELETE' })).status).toBe(404);
    jar.clear();
    expect((await call(`/api/admin/users/${otherId}/sessions/other-session`, { method: 'DELETE' })).status).toBe(401);
  });
});
