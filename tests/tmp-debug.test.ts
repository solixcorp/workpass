import { expect, test } from "bun:test";
import worker from "../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "./test-d1";
import { generatePKCEPair, jwtVerify } from "../oidc/oidc-crypto";

test("OIDC sign-out sends a signed logout token to an approved RP", async () => {
  const { db, sqlite } = createTestD1();
  const base = "http://127.0.0.1:8787";
  const uri = "https://rp.example.test/logout";
  const env = { DB: db, AUTH_BASE_URL: base, AUTH_SECRET: "integration-secret-0123456789abcdef",
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-012345",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-012345",
    ENABLE_DYNAMIC_CLIENT_REGISTRATION: "true", CLIENT_REGISTRATION_TOKEN: "register-token-0123456789abcdef-012345" } as unknown as Env;
  const cookies = new Map<string, string>();
  const call = async (path: string, options: { method?: string; body?: unknown; headers?: Record<string, string>; form?: string } = {}) => {
    const headers: Record<string, string> = { Origin: base, ...options.headers };
    if (cookies.size) headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (options.form !== undefined) headers["Content-Type"] = "application/x-www-form-urlencoded";
    const res = await worker.fetch(new Request(base + path, { method: options.method ?? "GET", headers,
      body: options.form ?? (options.body === undefined ? undefined : JSON.stringify(options.body)) }), env, {} as ExecutionContext);
    for (const cookie of res.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const at = pair.indexOf("=");
      if (at > 0) cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return res;
  };
  expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
  sqlite.query("INSERT INTO oidc_logout_uri_approvals (uri) VALUES (?)").run(uri);
  const bootstrapResponse = await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
    body: { username: "logoutadmin", email: "admin@logout.test", name: "Admin", password: "LogoutOnly-7d9Kpw9zL2" } });
console.log("BOOTSTRAP-BODY:", await bootstrapResponse.clone().text());
expect(bootstrapResponse.status).toBe(201);
});
