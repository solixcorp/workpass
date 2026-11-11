import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { ensureSsfDispatchTables } from "../../src/ssf/dispatch";
import { ensureSsfInboxTable } from "../../src/ssf/inbox";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Integrations-7d9Kpw9zL2xQ";
const secrets = ["outbound-token-never-return-this", "inbound-token-never-return-this-1234", "management-token-never-return-this", "delivery-token-never-return-this", "signed-event-never-return-this"];

describe("integration administrator views", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "integrations-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
    ENABLE_SCIM_PROVISIONING: "true", SCIM_TARGET_ID: "target", SCIM_BASE_URL: "https://scim.example.test/private?token=hidden",
    SCIM_BEARER_TOKEN: secrets[0], ENABLE_INBOUND_SCIM: "true", INBOUND_SCIM_BEARER_TOKEN: secrets[1],
    ENABLE_SSF_SENDER: "true", ENABLE_SSF_RECEIVER: "true", SSF_MANAGEMENT_TOKEN: secrets[2],
    SSF_STREAMS: JSON.stringify([{ id: "incoming", issuer: "https://issuer.example", audience: "receiver", jwks: { keys: [] }, event_types: ["event"], delivery_token: secrets[3] }]),
    ENABLE_ACCOUNT_CLAIMS: "true", ENABLE_ATTRIBUTE_CLAIMS: "false", ENABLE_SCIM_ATTRIBUTE_RELEASE: "true",
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
    adminId = (await json(await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` }, body: { email: "admin@integrations.test", name: "Admin", username: "intadmin", password: PASSWORD } }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "intadmin", password: PASSWORD } })).status).toBe(200);
    for (const [id, status, date] of [["one", "succeeded", "2026-01-01"], ["two", "failed", "2026-01-02"], ["three", "failed", "2026-01-03"]]) {
      await db.prepare("INSERT INTO scim_operations (id, target_id, user_id, operation, status, created_at, updated_at) VALUES (?, 'target', ?, 'update', ?, ?, ?)").bind(id, adminId, status, date, date).run();
    }
    await ensureSsfDispatchTables(db);
    await ensureSsfInboxTable(db);
    await db.prepare("INSERT INTO ssf_recipients VALUES ('outgoing', 'aud', ?, '[]', ?, 0, 1700000000000)").bind(`https://remote.example/path?secret=${secrets[3]}`, secrets[3]).run();
    await db.prepare("INSERT INTO ssf_deliveries VALUES ('d1', 'outgoing', 'set1', ?, 'delivered', 1, 0, 200, ?, 1700000000000, 1700000000000)").bind(secrets[4], secrets[3]).run();
    await db.prepare("INSERT INTO ssf_inbox VALUES ('incoming', 'issuer', 'i1', 'hash', ?, 'pending', 1700000001)").bind(secrets[4]).run();
    for (const [slug, name, binding] of [["first", "First App", "client-one"], ["second", "Second App", "client-two"]]) {
      await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, created_by, created_at, updated_at) VALUES (?, ?, ?, 'oidc', ?, ?, '2026-01-01', '2026-01-01')").bind(slug, slug, name, binding, adminId).run();
    }
    expect((await call("/api/admin/claim-release-policies/oidc%3Aclient-one", { method: "PUT", body: { allowAccountClaims: false } })).status).toBe(200);
  });

  test("status reports flags, safe configuration and activity", async () => {
    const response = await call("/api/admin/integrations/status");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    const body = await json(response);
    expect(body.scimOutbound).toMatchObject({ enabled: true, configured: false, baseUrlHost: "scim.example.test", operationCounts: { failed: 2, succeeded: 1 }, lastActivityAt: "2026-01-03" });
    expect(body.ssfSender).toMatchObject({ enabled: true, streamCount: 1 });
    expect(body.ssfReceiver).toMatchObject({ enabled: true, configured: true, streamCount: 1 });
    expect(body.claims).toMatchObject({ accountClaimsEnabled: true, attributeClaimsEnabled: false, scimAttributeReleaseEnabled: true });
  });

  test("SCIM journal filters and pages with resolved user", async () => {
    const first = await json(await call(`/api/admin/scim-operations?status=failed&userId=${adminId}&limit=1`));
    expect(first).toMatchObject({ total: 2, page: 1, limit: 1, operations: [{ id: "three", user_name: "Admin", user_email: "admin@integrations.test" }] });
    expect((await json(await call(`/api/admin/scim-operations?status=failed&userId=${adminId}&limit=1&page=2`))).operations[0].id).toBe("two");
    expect((await json(await call("/api/admin/scim-operations?userId=missing"))).total).toBe(0);
    expect((await call("/api/admin/scim-operations?limit=101")).status).toBe(400);
    expect((await call("/api/admin/scim-operations?status=wrong")).status).toBe(400);
  });

  test("streams and event journal omit credentials and page across directions", async () => {
    const streams = (await json(await call("/api/admin/ssf/streams"))).streams;
    expect(streams).toContainEqual(expect.objectContaining({ id: "outgoing", direction: "sender", endpointHost: "remote.example", eventsDelivered: 1, eventsFailed: 0 }));
    expect(streams).toContainEqual(expect.objectContaining({ id: "incoming", direction: "receiver", createdAt: null, eventsDelivered: null }));
    expect(await json(await call("/api/admin/ssf/events?limit=1"))).toMatchObject({ total: 2, page: 1, events: [{ id: "i1", direction: "receiver" }] });
    expect(await json(await call("/api/admin/ssf/events?limit=1&page=2"))).toMatchObject({ events: [{ id: "d1", direction: "sender" }] });
    expect((await call("/api/admin/ssf/events?page=0")).status).toBe(400);
  });

  test("policy list resolves apps and shows flag-only defaults", async () => {
    const body = await json(await call("/api/admin/claim-release-policies"));
    expect(body.policies).toContainEqual(expect.objectContaining({ subject: "oidc:client-one", applicationName: "First App", applicationSlug: "first", allowAccountClaims: false }));
    expect(body.applicationsWithoutPolicy).toContainEqual(expect.objectContaining({ subject: "oidc:client-two", applicationName: "Second App", defaults: { allowAccountClaims: true, allowUserAttributes: false, allowAccountAttributes: true, allowGroupAttributes: false, attributeAllowlist: null } }));
  });

  test("all views are no-store and never contain configured secrets", async () => {
    for (const path of ["/api/admin/integrations/status", "/api/admin/scim-operations", "/api/admin/ssf/streams", "/api/admin/ssf/events", "/api/admin/claim-release-policies"]) {
      const response = await call(path);
      expect(response.status).toBe(200);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      const text = await response.text();
      for (const secret of secrets) expect(text).not.toContain(secret);
    }
  });

  test("all views reject unauthenticated callers", async () => {
    jar.clear();
    for (const path of ["/api/admin/integrations/status", "/api/admin/scim-operations", "/api/admin/ssf/streams", "/api/admin/ssf/events", "/api/admin/claim-release-policies"]) {
      const response = await call(path);
      expect(response.status).toBe(401);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }
  });
});
