import { beforeAll, describe, expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import type { AuthInstance } from "../../src/auth/config";
import { createTestD1 } from "../test-d1";
import { bindSessionNetwork } from "../../src/security/session-geo-binding";
import { handleFingerprintRiskLogin } from "../../src/security/risk-auth-middleware";
import { DEFAULT_LOCATION_POLICY, saveLocationPolicy } from "../../src/security/location-policy";

const origin = "http://127.0.0.1:8787";
const execution = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

describe("session and passkey location enforcement", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "session-test-secret-0123456789abcdef0123456789", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", SESSION_BINDING_MODE: "enforce", SESSION_BINDING_NETWORK: "asn", SESSION_BINDING_GEOIP: "off" } as unknown as Env;
  let userId: string;
  let cookie: string;
  let token: string;
  async function post(path: string, body: unknown, bearer?: string) {
    return worker.fetch(new Request(origin + path, { method: "POST", headers: { origin, "content-type": "application/json", ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) }, body: JSON.stringify(body) }), env, execution);
  }
  function request(asn: number) {
    const req = new Request(origin + "/api/auth/get-session", { headers: { cookie, "cf-connecting-ip": "198.51.100.1" } });
    Object.defineProperty(req, "cf", { value: { asn } });
    return req;
  }
  beforeAll(async () => {
    expect((await post("/_internal/migrate", {}, env.MIGRATION_TOKEN)).status).toBe(200);
    const created = await post("/api/admin/bootstrap", { email: "geo@example.test", name: "Admin", username: "geoadmin", password: "SelfSvc-7d9Kpw9zL2xQ" }, env.ADMIN_BOOTSTRAP_TOKEN);
    userId = ((await created.json()) as any).user.id;
    const login = await post("/api/auth/sign-in/username", { username: "geoadmin", password: "SelfSvc-7d9Kpw9zL2xQ" });
    expect(login.status).toBe(200);
    cookie = login.headers.getSetCookie().find((c) => c.includes("session_token="))!.split(";")[0]!;
    token = (await db.prepare('SELECT token FROM "session" WHERE "userId" = ?').bind(userId).first<{ token: string }>())!.token;
  });

  test("unbound session is allowed; observe records drift without deletion", async () => {
    expect((await worker.fetch(request(1), env, execution)).status).toBe(200);
    await bindSessionNetwork({ env, sessionToken: token, userId, request: request(1) });
    const observe = { ...env, SESSION_BINDING_MODE: "observe" } as Env;
    expect((await worker.fetch(request(2), observe, execution)).status).toBe(200);
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(token).first()).not.toBeNull();
  });

  test("binding evaluation failure fails closed", async () => {
    const broken = { ...env, DB: new Proxy(db, { get(target, key) {
      if (key === "prepare") return (sql: string) => { if (sql.includes("FROM session_network_bindings")) throw new Error("unavailable"); return target.prepare(sql); };
      return Reflect.get(target, key);
    } }) } as Env;
    expect((await worker.fetch(request(2), broken, execution)).status).toBe(503);
  });

  test("get-session drift revokes session and companion rows", async () => {
    await db.prepare("INSERT INTO session_mfa_proofs (session_token, user_id, verified_at) VALUES (?, ?, ?)").bind(token, userId, new Date().toISOString()).run();
    expect((await worker.fetch(request(2), env, execution)).status).toBe(401);
    for (const table of ["session_mfa_proofs", "session_network_bindings", "session_step_up_requirements", "account_session_contexts"]) {
      expect(await db.prepare(`SELECT session_token FROM ${table} WHERE session_token = ?`).bind(token).first()).toBeNull();
    }
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(token).first()).toBeNull();
  });

  test("successful risk-branch passkey login checks location before returning", async () => {
    await db.prepare("INSERT INTO location_places (id, name, latitude, longitude, radius_m, enabled, created_by, created_at, updated_at) VALUES ('office', 'Office', 37, 127, 100, 1, ?, ?, ?)").bind(userId, new Date().toISOString(), new Date().toISOString()).run();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "enforce", signal: "network", networkMarginKm: 0 }, userId);
    for (const [latitude, expected, mode] of [[37, 200, "enforce"], [35, 200, "observe"], [35, 403, "enforce"]] as const) {
      await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode, signal: "network", networkMarginKm: 0 }, userId);
      const login = await post("/api/auth/sign-in/username", { username: "geoadmin", password: "SelfSvc-7d9Kpw9zL2xQ" });
      const issued = (await login.clone().json() as any).token as string;
      const fakeAuth = { handler: async () => Response.json({ token: issued, user: { id: userId } }) } as unknown as AuthInstance;
      const req = new Request(origin + "/api/auth/passkey/verify-authentication", { method: "POST", body: "{}" });
      Object.defineProperty(req, "cf", { value: { latitude, longitude: 127 } });
      const result = await handleFingerprintRiskLogin(req, env, fakeAuth, "authentication.passkey.success_or_failure");
      expect(result.status).toBe(expected);
      expect(!!(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(issued).first())).toBe(expected === 200);
    }
    const login = await post("/api/auth/sign-in/username", { username: "geoadmin", password: "SelfSvc-7d9Kpw9zL2xQ" });
    const issued = (await login.json() as any).token as string;
    const broken = { ...env, DB: new Proxy(db, { get(target, key) {
      if (key === "prepare") return (sql: string) => { if (sql.includes("FROM location_group_rules")) throw new Error("unavailable"); return target.prepare(sql); };
      return Reflect.get(target, key);
    } }) } as Env;
    const req = new Request(origin + "/api/auth/passkey/verify-authentication", { method: "POST", body: "{}" });
    const fakeAuth = { handler: async () => Response.json({ token: issued, user: { id: userId } }) } as unknown as AuthInstance;
    expect((await handleFingerprintRiskLogin(req, broken, fakeAuth, "authentication.passkey.success_or_failure")).status).toBe(403);
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(issued).first()).toBeNull();
  });
});
