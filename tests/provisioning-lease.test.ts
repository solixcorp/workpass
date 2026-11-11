import { beforeAll, describe, expect, test } from "bun:test";
import worker from "../src/index";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

describe("provisioning sync lease", () => {
  const { db, sqlite } = createTestD1();
  const origin = "http://127.0.0.1:8787";
  const path = "/api/admin/applications/lease/provisioning";
  const env = { DB: db, AUTH_BASE_URL: origin, AUTH_SECRET: "lease-secret-0123456789abcdef0123456789", ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-012345", ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-012345", ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(9))) } as unknown as Env;
  const jar = new Map<string, string>();
  async function call(url: string, method = "GET", body?: unknown, auth = true) {
    const headers: Record<string, string> = { Origin: origin };
    if (auth && jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (url === "/_internal/migrate") headers.Authorization = `Bearer ${env.MIGRATION_TOKEN}`;
    if (url === "/api/admin/bootstrap") headers.Authorization = `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}`;
    const response = await worker.fetch(new Request(origin + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, {} as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) { const pair = cookie.split(";")[0]!; const i = pair.indexOf("="); if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1)); }
    return response;
  }
  const setLock = async (at: string | null) => { await db.prepare("UPDATE app_provisioning_targets SET sync_lock = 1, sync_lock_owner = 'old', sync_lock_at = ? WHERE slug = 'lease'").bind(at).run(); };
  const row = () => db.prepare("SELECT sync_lock, sync_lock_owner, sync_lock_at, last_sync_at FROM app_provisioning_targets WHERE slug = 'lease'").first<{ sync_lock: number; sync_lock_owner: string | null; sync_lock_at: string | null; last_sync_at: string | null }>();
  beforeAll(async () => {
    expect((await call("/_internal/migrate", "POST")).status).toBe(200);
    expect((await call("/api/admin/bootstrap", "POST", { username: "leaseadmin", email: "admin@lease.test", name: "Admin", password: "LeaseOnly-7d9Kpw9zL2" })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", "POST", { username: "leaseadmin", password: "LeaseOnly-7d9Kpw9zL2" })).status).toBe(200);
    await db.prepare("INSERT INTO applications (id, slug, name, protocol, launch_url, enabled, created_by, created_at, updated_at) VALUES ('lease', 'lease', 'Lease', 'bookmark', 'https://example.test', 1, 'admin', '2026', '2026')").run();
    expect((await call(path, "PUT", { baseUrl: "https://scim.example.test", bearerToken: "token", enabled: true })).status).toBe(200);
  });
  test("fresh lease is refused and visible; anonymous requests are denied", async () => {
    await setLock(new Date().toISOString());
    expect(await (await call(path)).json()).toMatchObject({ syncRunning: true, lastSyncAt: null });
    const response = await call(`${path}/sync`, "POST");
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "이미 동기화가 진행 중입니다. 잠시 뒤 다시 시도하세요." });
    expect((await call(path, "GET", undefined, false)).status).toBe(401);
    expect((await call(`${path}/sync`, "POST", undefined, false)).status).toBe(401);
  });
  test("stale lease is taken over, audited and released after success", async () => {
    await setLock(new Date(Date.now() - 360_000).toISOString());
    expect(await (await call(path)).json()).toMatchObject({ syncRunning: false });
    const original = globalThis.fetch;
    try {
      globalThis.fetch = (async () => Response.json({ id: "remote" }, { status: 201 })) as typeof fetch;
      expect((await call(`${path}/sync`, "POST")).status).toBe(200);
    } finally { globalThis.fetch = original; }
    expect(await row()).toMatchObject({ sync_lock: 0, sync_lock_owner: null, sync_lock_at: null });
    expect(await (await call(path)).json()).toMatchObject({ syncRunning: false, lastSyncAt: (await row())!.last_sync_at });
    expect((await row())!.last_sync_at).not.toBeNull();
    expect(await db.prepare("SELECT event_type FROM audit_events WHERE event_type = 'app.provisioning.sync_lease_taken_over'").first()).not.toBeNull();
  });
  test("two simultaneous stale takeovers have one winner", async () => {
    await setLock(new Date(Date.now() - 360_000).toISOString());
    const original = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
      const responses = await Promise.all([call(`${path}/sync`, "POST"), call(`${path}/sync`, "POST")]);
      expect(responses.map((r) => r.status).sort()).toEqual([200, 409]);
    } finally { globalThis.fetch = original; }
  });
  test("failure during a batch releases the lease", async () => {
    sqlite.exec("CREATE TRIGGER lease_fail BEFORE UPDATE OF sync_lock_at ON app_provisioning_targets WHEN OLD.sync_lock = 1 AND NEW.sync_lock = 1 BEGIN SELECT RAISE(ABORT, 'injected heartbeat failure'); END");
    try { expect((await call(`${path}/sync`, "POST")).status).toBe(500); }
    finally { sqlite.exec("DROP TRIGGER lease_fail"); }
    expect(await row()).toMatchObject({ sync_lock: 0, sync_lock_owner: null, sync_lock_at: null });
  });
  test("heartbeat extends the lease between users", async () => {
    const now = new Date().toISOString();
    await db.prepare('INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", banned) VALUES (?, ?, ?, 0, ?, ?, 1)').bind("zz-heartbeat", "Heartbeat", "heartbeat@example.test", now, now).run();
    const old = new Date(Date.now() - 240_000).toISOString();
    // After the first renewal, age the timestamp; the next user must renew it again.
    sqlite.exec(`CREATE TRIGGER lease_age AFTER UPDATE OF sync_lock_at ON app_provisioning_targets WHEN OLD.sync_lock = 1 AND NEW.sync_lock = 1 AND OLD.sync_lock_at != '${old}' BEGIN UPDATE app_provisioning_targets SET sync_lock_at = '${old}' WHERE slug = NEW.slug; END`);
    // Record each renewal independently, including the second user's heartbeat.
    sqlite.exec("CREATE TABLE lease_heartbeats (at TEXT)");
    sqlite.exec("CREATE TRIGGER lease_record AFTER UPDATE OF sync_lock_at ON app_provisioning_targets WHEN OLD.sync_lock = 1 AND NEW.sync_lock = 1 BEGIN INSERT INTO lease_heartbeats VALUES (NEW.sync_lock_at); END");
    const original = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
      expect((await call(`${path}/sync`, "POST")).status).toBe(200);
      const beats = await db.prepare("SELECT at FROM lease_heartbeats WHERE at > ?").bind(old).all();
      expect(beats.results.length).toBeGreaterThanOrEqual(2);
    } finally { globalThis.fetch = original; sqlite.exec("DROP TRIGGER lease_age"); sqlite.exec("DROP TRIGGER lease_record"); }
  });
});
