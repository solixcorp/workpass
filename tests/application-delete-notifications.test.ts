import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../src/index";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";
import { ensureApplicationTables } from "../src/db/schema";

const origin = "http://127.0.0.1:8787";
const { db, sqlite } = createTestD1();
const env = {
  DB: db, AUTH_SECRET: "integration-secret-0123456789abcdef-0123456", AUTH_BASE_URL: origin,
  ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
  ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
  ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
} as unknown as Env;
const jar = new Map<string, string>();
async function call(path: string, method = "GET", body?: unknown, headers: Record<string, string> = {}) {
  const response = await mod.fetch(new Request(origin + path, {
    method, headers: { ...headers, Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "), ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  }), env, { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext);
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
    if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
  return response;
}

describe("application deletion", () => {
  beforeAll(async () => {
    expect((await call("/_internal/migrate", "POST", undefined, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
    expect((await call("/api/admin/bootstrap", "POST", { email: "admin@delete.test", name: "Admin", username: "deleteadmin", password: "Delete-7d9Kpw9zL2" }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", "POST", { username: "deleteadmin", password: "Delete-7d9Kpw9zL2" })).status).toBe(200);
  });
  async function create(slug: string, binding?: string) {
    if (!binding) {
      const response = await call("/api/admin/oidc-clients", "POST", { name: slug, applicationType: "spa", redirectUris: ["https://example.com/cb"] });
      expect(response.status).toBe(201);
      binding = ((await response.json()) as any).client.clientId;
    }
    expect((await call("/api/admin/applications", "POST", { slug, name: slug, protocol: "oidc", binding })).status).toBe(201);
    return binding!;
  }
  test("removes an unshared client and its tokens and pending grants", async () => {
    const client = await create("delete-client");
    // Real client-credentials token exercises the provider's actual token schema.
    const service = await call("/api/admin/oidc-clients", "POST", { name: "service", applicationType: "service", scopes: ["reports.read"] });
    const { client: svc, clientSecret } = await service.json() as any;
    await db.prepare('UPDATE "oauthClient" SET disabled = 0 WHERE clientId = ?').bind(svc.clientId).run();
    expect((await call("/api/admin/applications", "POST", { slug: "delete-service", name: "service", protocol: "oidc", binding: svc.clientId })).status).toBe(201);
    const token = await mod.fetch(new Request(origin + "/api/auth/oauth2/token", { method: "POST", headers: { Authorization: `Basic ${btoa(`${svc.clientId}:${clientSecret}`)}`, "Content-Type": "application/x-www-form-urlencoded" }, body: "grant_type=client_credentials&scope=reports.read" }), env, { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext);
    expect(token.status).toBe(200);
    expect(await db.prepare('SELECT 1 FROM "oauthAccessToken" WHERE clientId = ?').bind(svc.clientId).first()).not.toBeNull();
    await db.prepare('INSERT INTO "oauthConsent" (id, clientId, scopes, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)').bind("delete-consent", svc.clientId, "openid", Date.now(), Date.now()).run();
    const response = await call("/api/admin/applications/delete-service", "DELETE");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ deleted: true, providerRemoved: true, providerKind: "oidc", providerShared: false });
    expect(await db.prepare('SELECT 1 FROM "oauthAccessToken" WHERE clientId = ?').bind(svc.clientId).first()).toBeNull();
    expect(await db.prepare('SELECT 1 FROM "oauthConsent" WHERE clientId = ?').bind(svc.clientId).first()).toBeNull();
    expect(await db.prepare('SELECT 1 FROM "oauthClient" WHERE clientId = ?').bind(svc.clientId).first()).toBeNull();
    expect((await call("/api/admin/applications/delete-client", "DELETE")).status).toBe(200);
    expect(await db.prepare('SELECT 1 FROM "oauthClient" WHERE clientId = ?').bind(client).first()).toBeNull();
  });
  test("retains shared providers", async () => {
    const client = await create("shared-one");
    await create("shared-two", client);
    const response = await call("/api/admin/applications/shared-one", "DELETE");
    expect(await response.json()).toEqual({ deleted: true, providerRemoved: false, providerKind: "oidc", providerShared: true });
    expect(await db.prepare('SELECT 1 FROM "oauthClient" WHERE clientId = ?').bind(client).first()).not.toBeNull();
  });
  test("refuses WorkPass deletion and protects its client through another app", async () => {
    expect((await call("/api/admin/applications/workpass-dashboard", "DELETE")).status).toBe(409);
    const client = (await db.prepare("SELECT value FROM app_settings WHERE key = 'workpass.client_id'").first<{ value: string }>())!.value;
    await create("workpass-alias", client);
    const response = await call("/api/admin/applications/workpass-alias", "DELETE");
    expect(await response.json()).toMatchObject({ deleted: true, providerRemoved: false, providerKind: "oidc" });
    expect(await db.prepare('SELECT 1 FROM "oauthClient" WHERE clientId = ?').bind(client).first()).not.toBeNull();
  });
  test("provider failure leaves the application and provider intact", async () => {
    const client = await create("failure-client");
    sqlite.exec(`CREATE TRIGGER test_reject_client_delete BEFORE DELETE ON oauthClient WHEN OLD.clientId = '${client}' BEGIN SELECT RAISE(ABORT, 'injected failure'); END`);
    const response = await call("/api/admin/applications/failure-client", "DELETE");
    expect(response.status).toBe(500);
    expect((await response.json() as any).error).toContain("삭제하지 못했습니다");
    expect(await db.prepare("SELECT 1 FROM applications WHERE slug = ?").bind("failure-client").first()).not.toBeNull();
    expect(await db.prepare('SELECT 1 FROM "oauthClient" WHERE clientId = ?').bind(client).first()).not.toBeNull();
  });
  test("revoking access notifies the requester at their requests page", async () => {
    sqlite.exec(`INSERT INTO request_rules (id, name, created_by, created_at) VALUES ('rule-revoke', 'revoke-test', 'admin', '2026');
      INSERT INTO request_rule_bindings (id, subject, rule_id, pending_expiry_seconds, max_granted_expiry_seconds, created_by, created_at)
      VALUES ('binding-revoke', 'oidc:revoke-test', 'rule-revoke', 60, 3600, 'admin', '2026');
      INSERT INTO access_requests (id, subject, user_id, binding_id, justification, status, requested_expiry_seconds, pending_expires_at, created_at)
      VALUES ('request-revoke', 'oidc:revoke-test', 'requester', 'binding-revoke', 'test', 'approved', 3600, '2099', '2026');
      INSERT INTO app_temporal_grants (request_id, subject, user_id, granted_at, expires_at, approved_by)
      VALUES ('request-revoke', 'oidc:revoke-test', 'requester', '2026', '2099', 'admin');`);
    expect((await call('/api/admin/access-requests/request-revoke/revoke', 'POST')).status).toBe(200);
    expect(await db.prepare("SELECT link FROM user_notifications WHERE user_id = ?").bind("requester").first()).toEqual({ link: "/requests" });
  });
});

test("retention and SCIM indexes are idempotent and usable", async () => {
  const testDb = createTestD1();
  const testEnv = { DB: testDb.db } as Env;
  await ensureApplicationTables(testEnv);
  await ensureApplicationTables(testEnv);
  for (const [query, index] of [
    ["SELECT * FROM scim_operations WHERE status = 'pending' ORDER BY created_at", "scim_operations_status_created_idx"],
    ["SELECT * FROM scim_operations WHERE target_id = 'x' ORDER BY created_at", "scim_operations_target_created_idx"],
    ["DELETE FROM login_history WHERE occurred_at < '2026'", "login_history_occurred_idx"],
    ["DELETE FROM user_notifications WHERE read_at IS NOT NULL AND read_at < '2026'", "user_notifications_read_idx"],
  ]) {
    const plan = testDb.sqlite.query(`EXPLAIN QUERY PLAN ${query}`).all();
    expect(JSON.stringify(plan)).toContain(index);
  }
});

test("notification link literals resolve to SPA routes", async () => {
  // Keep this allow-list in sync with web/src/router.tsx, including nested admin paths.
  const routes = new Set(["/", "/security", "/me", "/activity", "/requests", "/admin/access-requests", "/admin/users/$id"]);
  const found: string[] = [];
  for await (const file of new Bun.Glob("**/*.ts").scan({ cwd: "src" })) {
    const source = await Bun.file(`src/${file}`).text();
    for (const match of source.matchAll(/\blink\s*:\s*(["'`])(\/[^"'`]*?)\1/g)) {
      const route = match[2]!.replace(/\$\{[^}]+\}/g, "$id");
      found.push(route);
      expect(routes.has(route)).toBe(true);
    }
  }
  expect(found.length).toBeGreaterThan(0);
  const requests = await Bun.file("src/access/request-routes.ts").text();
  expect(requests).toMatch(/notifyUsers\(context\.env, reviewers,[^\n]+link: "\/requests"/);
  expect(requests).toMatch(/link: "\/requests"/);
});
