import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../src/index";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";
import { validProvisioningUrl } from "../src/provisioning/routes";
import { executeScimOperation, loadScimExecutorConfig } from "../src/scim/executor";

const ORIGIN = "http://127.0.0.1:8787";
const TOKEN = "secret-provisioning-token-123456";
describe("application provisioning", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "provisioning-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN, ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789", ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789", ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(9))) } as unknown as Env;
  const jar = new Map<string, string>();
  const path = "/api/admin/applications/example/provisioning";
  async function call(url: string, method = "GET", body?: unknown, authenticated = true) {
    const headers: Record<string, string> = {};
    if (authenticated && jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (method !== "GET") headers.Origin = ORIGIN;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (url === "/_internal/migrate") headers.Authorization = `Bearer ${env.MIGRATION_TOKEN}`;
    if (url === "/api/admin/bootstrap") headers.Authorization = `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}`;
    const response = await mod.fetch(new Request(`${ORIGIN}${url}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) { const [pair] = cookie.split(";"); const index = pair!.indexOf("="); if (index > 0) jar.set(pair!.slice(0, index), pair!.slice(index + 1)); }
    return response;
  }
  beforeAll(async () => {
    expect((await call("/_internal/migrate", "POST")).status).toBe(200);
    const bootstrap = await call("/api/admin/bootstrap", "POST", { email: "p@example.test", name: "Admin", username: "provisionadmin", password: "Provision-7d9Kpw9zL2xQ" });
    expect(bootstrap.status).toBe(201);
    expect((await call("/api/auth/sign-in/username", "POST", { username: "provisionadmin", password: "Provision-7d9Kpw9zL2xQ" })).status).toBe(200);
    await db.prepare("INSERT INTO applications (id, slug, name, protocol, launch_url, enabled, created_by, created_at, updated_at) VALUES ('app', 'example', 'Example', 'bookmark', 'https://example.test', 1, 'admin', '2026', '2026')").run();
  });
  test("rejects private and malformed URLs", () => {
    for (const url of ["http://example.com", "https://localhost", "https://sub.localhost", "https://127.0.0.1", "https://10.0.0.1", "https://172.16.2.1", "https://192.168.1.1", "https://169.254.1.1", "https://[::1]", "https://user:pass@example.com"]) expect(validProvisioningUrl(url)).toBe(false);
    expect(validProvisioningUrl("https://scim.example.test/v2")).toBe(true);
  });
  test("seals token and does not return it; requires sealing key", async () => {
    const key = env.AEAD_SEALING_KEY; env.AEAD_SEALING_KEY = undefined;
    expect((await call(path, "PUT", { baseUrl: "https://scim.example.test/v2", bearerToken: TOKEN, enabled: true })).status).toBe(409);
    env.AEAD_SEALING_KEY = key;
    const response = await call(path, "PUT", { baseUrl: "https://scim.example.test/v2", bearerToken: TOKEN, enabled: true });
    expect(response.status).toBe(200); expect(await response.text()).not.toContain(TOKEN);
    const row = await db.prepare("SELECT sealed_token FROM app_provisioning_targets WHERE slug = 'example'").first<{ sealed_token: string }>();
    expect(row!.sealed_token).not.toContain(TOKEN);
    const get = await call(path); expect(get.headers.get("Cache-Control")).toBe("no-store"); expect(await get.text()).not.toContain(TOKEN);
  });
  test("test endpoint handles success and masks failure", async () => {
    const original = globalThis.fetch;
    try {
      globalThis.fetch = (async (_url: unknown, init?: RequestInit) => { expect(init?.redirect).toBe("manual"); expect(new Headers(init?.headers).get("Authorization")).toBe(`Bearer ${TOKEN}`); return new Response("{}", { status: 200 }); }) as typeof fetch;
      expect(await (await call(`${path}/test`, "POST")).json()).toMatchObject({ ok: true, httpStatus: 200 });
      globalThis.fetch = (async () => { throw new Error(TOKEN); }) as typeof fetch;
      const failure = await (await call(`${path}/test`, "POST")).text(); expect(failure).not.toContain(TOKEN); expect(JSON.parse(failure).ok).toBe(false);
    } finally { globalThis.fetch = original; }
  });
  test("sync creates, updates and deactivates through journal", async () => {
    const original = globalThis.fetch; const bodies: any[] = [];
    try {
      globalThis.fetch = (async (_url: unknown, init?: RequestInit) => { bodies.push(JSON.parse(String(init?.body))); return init?.method === "POST" ? Response.json({ id: "remote-id" }, { status: 201 }) : new Response(null, { status: 204 }); }) as typeof fetch;
      expect(await (await call(`${path}/sync`, "POST")).json()).toMatchObject({ processed: 1, succeeded: 1, failed: 0, remaining: 0 });
      expect(await (await call(`${path}/sync`, "POST")).json()).toMatchObject({ succeeded: 1 });
      expect(bodies[0].active).toBe(true); expect(bodies[1].Operations[0].value.active).toBe(true);
      const operations = await (await call("/api/admin/scim-operations?applicationSlug=example")).json() as any;
      expect(operations.total).toBe(2); expect(operations.operations[0].applicationName).toBe("Example");
    } finally { globalThis.fetch = original; }
  });
  test("banned mapped user is deactivated and sync scans at most 50", async () => {
    const original = globalThis.fetch; const bodies: any[] = [];
    try {
      for (let i = 0; i < 51; i++) {
        const id = `test-${String(i).padStart(2, "0")}`;
        await db.prepare('INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", banned) VALUES (?, ?, ?, 0, ?, ?, 1)').bind(id, id, `${id}@example.test`, new Date().toISOString(), new Date().toISOString()).run();
      }
      await db.prepare("INSERT INTO scim_user_mappings (target_id, user_id, external_user_id, created_at) VALUES ('app:example', 'test-00', 'remote-test', '2026')").run();
      globalThis.fetch = (async (_url: unknown, init?: RequestInit) => { bodies.push(JSON.parse(String(init?.body))); return new Response(null, { status: 204 }); }) as typeof fetch;
      const first = await (await call(`${path}/sync`, "POST")).json() as any;
      expect(first.processed).toBe(50); expect(first.remaining).toBe(2);
      const second = await (await call(`${path}/sync`, "POST")).json() as any;
      expect(second.processed).toBe(2); expect(second.remaining).toBe(0);
      expect(bodies.some((body) => body.Operations?.[0]?.value?.active === false)).toBe(true);
    } finally { globalThis.fetch = original; }
  });
  test("open operations block duplicates and application deletion retains journal", async () => {
    await db.prepare("INSERT INTO scim_operations (id, target_id, user_id, operation, status, created_at, updated_at) VALUES ('locked', 'app:example', 'test-00', 'update', 'outcome_unknown', '2026', '2026')").run();
    const original = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
      const result = await (await call(`${path}/sync`, "POST")).json() as any;
      expect(result.failed).toBe(1);
      const count = await db.prepare("SELECT COUNT(*) AS count FROM scim_operations WHERE target_id = 'app:example' AND user_id = 'test-00' AND status IN ('pending', 'in_progress', 'outcome_unknown')").first<{ count: number }>();
      expect(count!.count).toBe(1);
      await db.prepare("DELETE FROM applications WHERE slug = 'example'").run();
      expect(await db.prepare("SELECT slug FROM app_provisioning_targets WHERE slug = 'example'").first()).toBeNull();
      expect(await db.prepare("SELECT id FROM scim_operations WHERE id = 'locked'").first()).not.toBeNull();
    } finally { globalThis.fetch = original; }
  });
  test("deployment target stays separate and cannot claim an app operation", async () => {
    const deployment = { ...env, ENABLE_SCIM_PROVISIONING: "true", SCIM_TARGET_ID: "deployment", SCIM_BASE_URL: "https://deployment.example.test", SCIM_BEARER_TOKEN: "deployment-token" } as Env;
    const config = loadScimExecutorConfig(deployment);
    expect(config?.targetId).toBe("deployment");
    await db.prepare("INSERT INTO scim_operations (id, target_id, user_id, operation, status, created_at, updated_at) VALUES ('app-pending', 'app:example', 'test-01', 'create', 'pending', '2026', '2026')").run();
    expect(await executeScimOperation(deployment, config!, "app-pending")).toBe(false);
    expect((await db.prepare("SELECT status FROM scim_operations WHERE id = 'app-pending'").first<{ status: string }>())?.status).toBe("pending");
  });
  test("requires administrator session", async () => {
    for (const [url, method] of [[path, "GET"], [path, "PUT"], [path, "DELETE"], [`${path}/test`, "POST"], [`${path}/sync`, "POST"]]) {
      const response = await call(url!, method!, undefined, false); expect(response.status).toBe(401); expect(response.headers.get("Cache-Control")).toBe("no-store");
    }
  });
});
