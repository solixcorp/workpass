import { beforeAll, describe, expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

describe("logout approvals", () => {
  const { db } = createTestD1();
  const origin = "http://127.0.0.1:8787";
  const env = { DB: db, AUTH_BASE_URL: origin, AUTH_SECRET: "integration-secret-0123456789abcdef", ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-012345", ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-012345", ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true" } as unknown as Env;
  const cookies = new Map<string, string>();
  async function call(path: string, method = "GET", body?: unknown, auth = true) {
    const headers: Record<string, string> = { Origin: origin };
    if (auth && cookies.size) headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (path === "/_internal/migrate") headers.Authorization = `Bearer ${env.MIGRATION_TOKEN}`;
    if (path === "/api/admin/bootstrap") headers.Authorization = `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}`;
    const response = await worker.fetch(new Request(origin + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, {} as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) { const pair = cookie.split(";")[0]!; const i = pair.indexOf("="); if (i > 0) cookies.set(pair.slice(0, i), pair.slice(i + 1)); }
    return response;
  }
  const path = "/api/admin/oidc-logout-approvals";
  const uri = "https://rp.example.test/logout?x=1";
  beforeAll(async () => {
    expect((await call("/_internal/migrate", "POST")).status).toBe(200);
    expect((await call("/api/admin/bootstrap", "POST", { username: "approvaladmin", email: "admin@approval.test", name: "Admin", password: "Approval-7d9Kpw9zL2" })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", "POST", { username: "approvaladmin", password: "Approval-7d9Kpw9zL2" })).status).toBe(200);
  });
  test("authentication and safe URI validation", async () => {
    const unauth = await call(path, "GET", undefined, false); expect(unauth.status).toBe(401); expect(unauth.headers.get("Cache-Control")).toBe("no-store");
    for (const uri of ["http://example.com", "https://localhost", "https://u:p@example.com", "https://example.com/#frag", "https://127.0.0.1", `https://example.com/${"x".repeat(2049)}`]) expect((await call(path, "POST", { uri })).status).toBe(400);
  });
  test("add, list usage, protect and remove", async () => {
    const add = await call(path, "POST", { uri }); expect(add.status).toBe(200); expect(add.headers.get("Cache-Control")).toBe("no-store"); expect(await add.json()).toEqual({ approval: { uri, inUseBy: [] } });
    expect((await call(path, "POST", { uri })).status).toBe(409);
    const client = await call("/api/admin/oidc-clients", "POST", { name: "RP", applicationType: "web", redirectUris: ["https://rp.example.test/callback"], backchannelLogoutUri: uri });
    expect(client.status).toBe(201);
    const clientId = ((await client.json()) as any).client.clientId;
    expect(await (await call(path)).json()).toEqual({ approvals: [{ uri, inUseBy: [{ clientId, applicationName: "RP" }] }] });
    expect((await call(`${path}?uri=${encodeURIComponent(uri)}`, "DELETE")).status).toBe(409);
    expect((await call(`/api/admin/oidc-clients/${clientId}`, "PATCH", { backchannelLogoutUri: null })).status).toBe(200);
    expect(await (await call(`${path}?uri=${encodeURIComponent(uri)}`, "DELETE")).json()).toEqual({ deleted: true });
    const events = await db.prepare("SELECT event_type, outcome FROM audit_events WHERE event_type LIKE 'oidc.logout_approval.%'").all<{ event_type: string; outcome: string }>();
    expect(events.results).toEqual(expect.arrayContaining([{ event_type: "oidc.logout_approval.add", outcome: "success" }, { event_type: "oidc.logout_approval.remove", outcome: "success" }]));
  });
});
