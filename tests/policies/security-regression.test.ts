import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { evaluateLoginSurface } from "../../src/policies/password-entry";
import { createTestD1 } from "../test-d1";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Strong-bootstrap-Password-9";

describe("policy security regressions", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "policy-test-secret-0123456789abcdef-0123456", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  async function call(path: string, method = "GET", body?: unknown, extra: Record<string, string> = {}) {
    const headers: Record<string, string> = { ...extra };
    if (method !== "GET") headers.Origin = ORIGIN;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";"); const i = pair!.indexOf("=");
      if (i > 0) jar.set(pair!.slice(0, i), pair!.slice(i + 1));
    }
    return response;
  }
  const bootstrap = (password: string) => call("/api/admin/bootstrap", "POST",
    { email: "admin@policy.test", name: "Admin", username: "policyadmin", password },
    { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` });

  beforeAll(async () => {
    expect((await call("/_internal/migrate", "POST", undefined, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
    await db.prepare("INSERT INTO policies (id, name, type, config, enabled, created_by, created_at) VALUES ('pw', 'pw', 'password', ?, 1, 'setup', ?)")
      .bind(JSON.stringify({ minLength: 20 }), new Date().toISOString()).run();
    await db.prepare("INSERT INTO policy_bindings (id, target, target_ref, policy_id, created_by, created_at) VALUES ('pw-bind', 'password_entry', '', 'pw', 'setup', ?)")
      .bind(new Date().toISOString()).run();
  });

  test("bootstrap rejects a violating plaintext password without claiming the slot", async () => {
    expect((await bootstrap("Weak1234")).status).toBe(400);
    expect(await db.prepare("SELECT slot FROM bootstrap_state WHERE slot = 1").first()).toBeNull();
    expect((await bootstrap(PASSWORD)).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", "POST", { username: "policyadmin", password: PASSWORD })).status).toBe(200);
  });

  test("global bindings created through management are selected, aliases rejected", async () => {
    const me = await (await call("/api/auth/get-session")).json() as any;
    for (const target of ["login", "password_entry"]) {
      expect((await call("/api/admin/policy-bindings", "POST", { target, targetRef: "default", bindUserId: me.user.id })).status).toBe(400);
    }
    const response = await call("/api/admin/policy-bindings", "POST", { target: "login", targetRef: "", bindUserId: me.user.id, negate: true });
    expect(response.status).toBe(201);
    expect((await evaluateLoginSurface(env, me.user.id)).passing).toBe(false);
  });

  test("password rules disclose server and OPAQUE enforcement scope", async () => {
    const response = await call("/api/admin/password-rules");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ enforcementScope: {
      plaintextPasswordWrites: "server_verified", opaqueActivation: "browser_advisory", opaquePasswordChange: "browser_advisory",
    } });
  });
});
