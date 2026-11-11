import { beforeAll, describe, expect, test } from "bun:test";
import { getOpaqueConfig, KE2, OpaqueClient, OpaqueID, RegistrationResponse, ScryptMemHardFn } from "@cloudflare/opaque-ts";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { performAccountLockdown } from "../../src/security/account-lockdown";
import { issueRecoveryToken } from "../../src/security/account-recovery";

const origin = "http://127.0.0.1:8787";
const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const wire = (a: number[]) => btoa(String.fromCharCode(...a)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unwire = (s: string) => Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

describe("OPAQUE self-service password change", () => {
  const { db } = createTestD1();
  const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(5)));
  const env = { DB: db, AUTH_SECRET: "password-change-secret-0123456789abcdef", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: key, OPAQUE_MASTER_KEY: key } as unknown as Env;
  let cookie = "", otherCookie = "", userId = "", clientId = "";
  const password = "Initial-password-9X!";
  async function call(path: string, body: unknown = {}, options: { cookie?: string; origin?: string; env?: Env } = {}) {
    return mod.fetch(new Request(origin + path, { method: "POST", headers: { "Content-Type": "application/json",
      Origin: options.origin ?? origin, Cookie: options.cookie ?? cookie }, body: JSON.stringify(body) }), options.env ?? env,
      { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext);
  }
  const body = async (r: Response): Promise<any> => await r.json();
  const cookieOf = (r: Response) => r.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
  async function registration(path: string, pass: string, extra: Record<string, unknown> = {}, sessionCookie = cookie) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const request = await client.registerInit(pass); if (request instanceof Error) throw request;
    const start = await call(path === "/api/me/password/register" ? `${path}-start` : `${path}/start`, { ...extra, registrationRequest: wire(request.serialize()) }, { cookie: sessionCookie });
    if (!start.ok) return { start, record: "" };
    const s = await body(start);
    const done = await client.registerFinish(RegistrationResponse.deserialize(config, unwire(s.registrationResponse)), s.serverIdentity, s.credentialIdentifier);
    if (done instanceof Error) throw done;
    return { start, record: wire(done.record.serialize()) };
  }
  async function verify(pass: string, useCookie = cookie) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const init = await client.authInit(pass); if (init instanceof Error) throw init;
    const start = await call("/api/me/password/verify-start", { ke1: wire(init.serialize()) }, { cookie: useCookie });
    const s = await body(start);
    if (!start.ok) return { start, finish: null, s };
    const done = await client.authFinish(KE2.deserialize(config, unwire(s.ke2)), s.serverIdentity, s.credentialIdentifier).catch(e => e);
    if (done instanceof Error) return { start, finish: null, s };
    const finish = await call("/api/me/password/verify-finish", { ke3: wire(done.ke3.serialize()), transcriptId: s.transcriptId }, { cookie: useCookie });
    return { start, finish, s };
  }
  async function clearLimits() { await db.prepare("DELETE FROM fingerprint_lookup_limits WHERE budget_key LIKE 'password_change:%'").run(); }

  beforeAll(async () => {
    const migrate = await mod.fetch(new Request(`${origin}/_internal/migrate`, { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}`, Origin: origin } }), env, {} as ExecutionContext);
    expect(migrate.status).toBe(200);
    const boot = await mod.fetch(new Request(`${origin}/api/admin/bootstrap`, { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}`, Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ email: "admin@change.test", username: "changeadmin", name: "Admin", password }) }), env, {} as ExecutionContext);
    expect(boot.status).toBe(201); userId = (await body(boot)).user.id;
    const login = () => call("/api/auth/sign-in/username", { username: "changeadmin", password });
    let response = await login(); expect(response.status).toBe(200); cookie = cookieOf(response);
    response = await login(); expect(response.status).toBe(200); otherCookie = cookieOf(response);
    const client = await call("/api/admin/oidc-clients", { name: "Change test", applicationType: "web", redirectUris: ["https://rp.example.test/callback"] });
    expect(client.status).toBe(201); clientId = (await body(client)).client.clientId;
    const first = await registration("/api/opaque/register", password);
    expect(first.start.status).toBe(200);
    expect((await call("/api/opaque/register/finish", { record: first.record })).status).toBe(201);
    env.ALLOW_PLAINTEXT_PASSWORD_LOGIN = "false";
  });

  test("legacy password endpoints are blocked by default and opt-in reaches better-auth", async () => {
    const before = await db.prepare('SELECT password FROM account WHERE "userId" = ? AND providerId = ?').bind(userId, "credential").first<{ password: string }>();
    for (const path of ["/api/auth/change-password", "/api/auth/set-password", "/api/auth/admin/set-user-password"]) {
      expect((await call(path, { currentPassword: password, newPassword: "Different-password-55!", userId })).status).toBe(404);
    }
    const after = await db.prepare('SELECT password FROM account WHERE "userId" = ? AND providerId = ?').bind(userId, "credential").first<{ password: string }>();
    expect(after?.password).toBe(before?.password);
    const enabled = { ...env, ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true" } as Env;
    expect((await call("/api/auth/change-password", { currentPassword: "wrong", newPassword: "Another-password-55!" }, { env: enabled })).status).not.toBe(404);
    expect((await call("/api/auth/admin/set-user-password", {}, { env: enabled })).status).not.toBe(404);
    expect((await call("/api/auth/change-password", { currentPassword: password, newPassword: "Changed-legacy-password-22!" }, { env: enabled })).status).toBe(200);
    // setPassword is server-only in the installed better-auth version.
  });

  test("recovery redemption still allows first enrollment after lockdown in plaintext mode", async () => {
    const enabled = { ...env, ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true" } as Env;
    const created = await call("/api/auth/admin/create-user", { email: "recover-change@test.test", password: "Before-lockdown-44!", name: "Recovery", role: "user" }, { env: enabled });
    expect(created.status).toBe(200);
    const target = (await body(created)).user.id as string;
    const locked = await performAccountLockdown({ env, userId: target, actorUserId: userId, source: "admin", reason: "test" });
    expect(locked.status).toBe("performed");
    const issued = await issueRecoveryToken({ env, userId: target, actorUserId: userId });
    if (issued.status !== "issued") throw new Error("recovery token not issued");
    const redeemed = await call("/api/security/account-recovery/redeem", { token: issued.recovery.token, new_password: "After-lockdown-55!" }, { cookie: "" });
    expect(redeemed.status).toBe(200);
    const login = await call("/api/auth/sign-in/email", { email: "recover-change@test.test", password: "After-lockdown-55!" }, { cookie: "", env: enabled });
    expect(login.status).toBe(200);
    const recoveredCookie = cookieOf(login);
    const first = await registration("/api/opaque/register", "New-opaque-password-99!", {}, recoveredCookie);
    expect(first.start.status).toBe(200);
    expect((await call("/api/opaque/register/finish", { record: first.record }, { cookie: recoveredCookie })).status).toBe(201);
  });

  test("administrator-issued activation tokens still enroll and replace credentials", async () => {
    const created = await call("/api/admin/users", { email: "activation-change@test.test", name: "New", sendEmail: false });
    expect(created.status).toBe(201);
    const data = await body(created); const target = data.user.id as string;
    let token = new URL(data.activation.activationUrl).hash.slice(1);
    let candidate = await registration("/api/activation/register", "Activation-password-9!", { token });
    expect((await call("/api/activation/register/finish", { token, record: candidate.record })).status).toBe(200);
    const newLink = await call(`/api/admin/users/${target}/activation-link`, { sendEmail: false });
    expect(newLink.status).toBe(200);
    token = new URL((await body(newLink)).activation.activationUrl).hash.slice(1);
    candidate = await registration("/api/activation/register", "Replacement-password-8!", { token });
    expect((await call("/api/activation/register/finish", { token, record: candidate.record })).status).toBe(200);
    expect((await call("/api/activation/register/finish", { token, record: candidate.record })).status).toBe(404);
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const ke1 = await client.authInit("Replacement-password-8!"); if (ke1 instanceof Error) throw ke1;
    const start = await body(await call("/api/opaque/auth/start", { username: "activation-change@test.test", ke1: wire(ke1.serialize()) }, { cookie: "" }));
    const proof = await client.authFinish(KE2.deserialize(config, unwire(start.ke2)), start.serverIdentity, "activation-change@test.test");
    if (proof instanceof Error) throw proof;
    const loggedIn = await call("/api/opaque/auth/finish", { username: "activation-change@test.test", ke3: wire(proof.ke3.serialize()), transcriptId: start.transcriptId }, { cookie: "" });
    expect(loggedIn.status).toBe(200);
    expect((await call("/api/auth/change-password", { currentPassword: "Replacement-password-8!", newPassword: "Plaintext-password-9!" }, { cookie: cookieOf(loggedIn) })).status).toBe(404);
    expect(await db.prepare('SELECT password FROM account WHERE "userId" = ? AND providerId = ?').bind(target, "credential").first()).toBeNull();
  });

  test("session-only registration cannot overwrite an enrolled credential", async () => {
    const candidate = await registration("/api/opaque/register", "Attacker-password-9!");
    expect((await call("/api/opaque/register/finish", { record: candidate.record })).status).toBe(403);
    const wrong = await verify("Attacker-password-9!"); expect(wrong.finish).toBeNull();
    expect((await verify(password)).finish?.status).toBe(200);
    await db.prepare("DELETE FROM opaque_password_confirmations").run(); await clearLimits();
  });

  test("wrong proof, origin and missing marker fail; marker binds to session and expires", async () => {
    for (const step of ["verify-start", "verify-finish", "register-start", "register-finish"]) {
      expect((await call(`/api/me/password/${step}`, {}, { origin: "https://evil.test" })).status).toBe(403);
    }
    expect((await call("/api/me/password/register-start")).status).toBe(403);
    expect((await call("/api/me/password/register-finish", { record: "AAAA" })).status).toBe(403);
    const wrong = await verify("wrong password"); expect(wrong.finish).toBeNull();
    expect((await call("/api/me/password/verify-finish", { transcriptId: wrong.s.transcriptId, ke3: "AAAA" })).status).toBe(401);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM opaque_password_confirmations").first<{ n: number }>())?.n).toBe(0);
    expect((await verify(password)).finish?.status).toBe(200);
    expect((await call("/api/me/password/register-start", {}, { cookie: otherCookie })).status).toBe(403);
    await db.prepare("UPDATE opaque_password_confirmations SET expires_at = ?").bind(new Date(Date.now() - 1000).toISOString()).run();
    expect((await call("/api/me/password/register-start")).status).toBe(403);
    expect((await call("/api/me/password/register-finish", { record: "AAAA" })).status).toBe(403);
    await clearLimits();
  });

  test("successful change is single-use, keeps current session, revokes others and notifies", async () => {
    const now = Date.now();
    await db.prepare("DELETE FROM user_notifications WHERE user_id = ? AND kind = 'security_password'").bind(userId).run();
    await db.prepare('INSERT INTO "oauthAccessToken" (id, token, clientId, userId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind("change-access", "change-access-token", clientId, userId, now + 3600000, now, '["openid"]').run();
    await db.prepare('INSERT INTO "oauthRefreshToken" (id, token, clientId, userId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind("change-refresh", "change-refresh-token", clientId, userId, now + 3600000, now, '["openid"]').run();
    await db.prepare("INSERT INTO trusted_devices (id, user_id, visitor_digest, label, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind("device", userId, "digest", "Device", new Date().toISOString(), new Date().toISOString(), new Date(now + 3600000).toISOString()).run();
    expect((await verify(password)).finish?.status).toBe(200);
    const next = await registration("/api/me/password/register", "Changed-password-8X!");
    expect(next.start.status).toBe(200);
    expect((await call("/api/me/password/register-finish", { record: next.record })).status).toBe(200);
    expect((await call("/api/me/password/register-finish", { record: next.record })).status).toBe(403);
    const sessions = await db.prepare('SELECT token FROM "session" WHERE "userId" = ?').bind(userId).all<{ token: string }>();
    expect(sessions.results).toHaveLength(1);
    expect((await db.prepare('SELECT revoked FROM "oauthAccessToken" WHERE id = ?').bind("change-access").first<{ revoked: number | null }>())?.revoked).not.toBeNull();
    expect((await db.prepare('SELECT revoked FROM "oauthRefreshToken" WHERE id = ?').bind("change-refresh").first<{ revoked: number | null }>())?.revoked).not.toBeNull();
    expect((await db.prepare("SELECT revoked_at FROM trusted_devices WHERE id = ?").bind("device").first<{ revoked_at: string | null }>())?.revoked_at).toBeNull();
    expect((await verify(password)).finish).toBeNull();
    expect((await verify("Changed-password-8X!")).finish?.status).toBe(200);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = ? AND outcome = 'success' AND request_path = ?").bind("identity.user.password_change.success_or_failure", "/api/me/password/register-finish").first<{ n: number }>())?.n).toBe(1);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE user_id = ? AND kind = 'security_password'").bind(userId).first<{ n: number }>())!.n).toBeGreaterThan(0);
    await clearLimits();
  });

  test("rate limit applies per user per phase", async () => {
    await clearLimits();
    for (let i = 0; i < 10; i++) expect((await call("/api/me/password/verify-start", {})).status).toBe(400);
    expect((await call("/api/me/password/verify-start", {})).status).toBe(429);
  });
});
