import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { openStepUpChallenge } from "../../src/security/step-up";
import { recordSessionMfaProof } from "../../src/mfa/second-factor";

const origin = "http://127.0.0.1:8787";
const password = "Removal-7d9Kpw9zL2xQ";

describe("administrator offboarding guards", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "removal-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";
  async function post(path: string, body: unknown, extra: Record<string, string> = {}) {
    const headers = new Headers({ Origin: origin, "Content-Type": "application/json", ...extra });
    if (jar.size) headers.set("Cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    const response = await mod.fetch(new Request(`${origin}${path}`, { method: "POST", headers, body: JSON.stringify(body) }), env,
      { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return response;
  }
  beforeAll(async () => {
    expect((await post("/_internal/migrate", {}, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
    const response = await post("/api/admin/bootstrap", { email: "admin@removal.test", name: "Admin", username: "removeadmin", password }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` });
    adminId = ((await response.json()) as { user: { id: string } }).user.id;
    expect((await post("/api/auth/sign-in/username", { username: "removeadmin", password })).status).toBe(200);
  });
  test("self deletion is rejected", async () => {
    const response = await post("/api/auth/admin/remove-user", { userId: adminId });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "자기 자신을 삭제할 수 없습니다." });
  });
  test("last administrator cannot be banned or demoted", async () => {
    expect((await post("/api/auth/admin/ban-user", { userId: adminId })).status).toBe(409);
    expect((await post("/api/auth/admin/set-role", { userId: adminId, role: "user" })).status).toBe(409);
  });
  test("wrong origin is rejected", async () => {
    expect((await post("/api/auth/admin/remove-user", { userId: adminId }, { Origin: "https://evil.example" })).status).toBe(403);
  });
  test("unimplemented removal fails closed without erasing user data", async () => {
    const created = await post("/api/auth/admin/create-user", { email: "person@removal.test", name: "Person", password });
    expect(created.status).toBe(200);
    const user = ((await created.json()) as { user: { id: string } }).user;
    const response = await post("/api/auth/admin/remove-user", { userId: user.id });
    expect(response.status).toBe(503);
    expect(await db.prepare('SELECT id FROM "user" WHERE id = ?').bind(user.id).first()).toBeTruthy();
  });
  test("banning revokes OAuth 1 access and temporary tokens", async () => {
    const created = await post("/api/auth/admin/create-user", { email: "ban@removal.test", name: "Banned", password });
    const user = ((await created.json()) as { user: { id: string } }).user;
    // These tables are normally initialized lazily by the OAuth 1 routes.
    await db.prepare(`CREATE TABLE IF NOT EXISTS oauth1_access_tokens (token TEXT PRIMARY KEY NOT NULL, consumer_key TEXT NOT NULL, user_id TEXT NOT NULL, sealed_secret TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, expires_at INTEGER)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS oauth1_temporary_tokens (token TEXT PRIMARY KEY NOT NULL, consumer_key TEXT NOT NULL, callback TEXT NOT NULL, verifier TEXT NOT NULL, sealed_secret TEXT NOT NULL, user_id TEXT, approved_at INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`).run();
    await db.prepare("INSERT INTO oauth1_access_tokens (token, consumer_key, user_id, sealed_secret, created_at) VALUES ('a', 'c', ?, 'secret', 1)").bind(user.id).run();
    await db.prepare("INSERT INTO oauth1_temporary_tokens (token, consumer_key, callback, verifier, sealed_secret, user_id, created_at, expires_at) VALUES ('t', 'c', 'oob', 'v', 'secret', ?, 1, 9999999999)").bind(user.id).run();
    expect((await post("/api/auth/admin/ban-user", { userId: user.id })).status).toBe(200);
    expect(await db.prepare("SELECT token FROM oauth1_access_tokens WHERE user_id = ? AND revoked = 0").bind(user.id).first()).toBeNull();
    expect(await db.prepare("SELECT token FROM oauth1_temporary_tokens WHERE user_id = ?").bind(user.id).first()).toBeNull();
  });
  test("proxy admin routes reject a pending challenge until this session verifies", async () => {
    const session = await db.prepare('SELECT token FROM "session" WHERE "userId" = ?').bind(adminId).first<{ token: string }>();
    expect(session).toBeTruthy();
    await openStepUpChallenge({ env, userId: adminId, sessionToken: session!.token, reasons: [], requestPath: "/" });
    expect((await post("/api/auth/admin/create-user", { email: "pending@removal.test", name: "Pending", password })).status).toBe(403);
    expect(await db.prepare('SELECT id FROM "user" WHERE email = ?').bind("pending@removal.test").first()).toBeNull();
    await recordSessionMfaProof(env, session!.token, adminId, "totp");
    expect((await post("/api/auth/admin/create-user", { email: "pending@removal.test", name: "Pending", password })).status).toBe(200);
  });
});
