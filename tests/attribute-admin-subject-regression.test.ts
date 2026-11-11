import { expect, test } from "bun:test";
import worker from "../src/index";
import type { Env } from "../src/env";
import { upsertSsfRecipient } from "../src/ssf/dispatch";
import { ATTRIBUTE_CHANGED_EVENT_TYPE } from "../src/ssf/attribute-events";
import { createTestD1 } from "./test-d1";

test("administrator PUT and DELETE name the changed user and group, not the administrator", async () => {
  const { db } = createTestD1();
  const origin = "http://127.0.0.1:8787";
  const env = { DB: db, AUTH_SECRET: "admin-test-secret-0123456789abcdef-0123456", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", ENABLE_SSF_SENDER: "true", SSF_MANAGEMENT_TOKEN: "ssf-management-token-0123456789abcdef",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))) } as unknown as Env;
  const jar = new Map<string, string>();
  const call = async (path: string, method = "GET", body?: unknown, extra: Record<string, string> = {}) => {
    const headers: Record<string, string> = { origin, ...extra };
    if (jar.size) headers.cookie = [...jar].map(([key, value]) => `${key}=${value}`).join("; ");
    if (body !== undefined) headers["content-type"] = "application/json";
    const response = await worker.fetch(new Request(origin + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const index = pair.indexOf("=");
      if (index > 0) jar.set(pair.slice(0, index), pair.slice(index + 1));
    }
    return response;
  };
  expect((await call("/_internal/migrate", "POST", undefined, { authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
  expect((await call("/api/admin/bootstrap", "POST", { email: "admin@example.test", name: "Admin", username: "subjectadmin", password: "Subject-7d9Kpw9zL2" }, { authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` })).status).toBe(201);
  expect((await call("/api/auth/sign-in/username", "POST", { username: "subjectadmin", password: "Subject-7d9Kpw9zL2" })).status).toBe(200);
  const created = await call("/api/admin/users", "POST", { email: "target@example.test", name: "Target", sendEmail: false });
  expect(created.status).toBe(201);
  const id = (await created.json() as { user: { id: string } }).user.id;
  await db.prepare("INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at) VALUES ('group-target', 'group', '', 'admin', '2026-01-01', '2026-01-01')").run();
  await upsertSsfRecipient(env, { id: "r", audience: "aud", endpoint: "https://recipient.test/set", eventTypes: [ATTRIBUTE_CHANGED_EVENT_TYPE] });
  const original = globalThis.fetch;
  const tokens: string[] = [];
  globalThis.fetch = (async (_url, init) => { tokens.push(String(init?.body)); return new Response(null, { status: 202 }); }) as typeof fetch;
  try {
    for (const path of [`/api/admin/attributes/user/${id}`, "/api/admin/attributes/group/group-target"]) {
      expect((await call(path, "PUT", { attributes: { team: "test" } })).status).toBe(200);
      expect((await call(path, "DELETE")).status).toBe(200);
    }
    const subjects = tokens.map((token) => JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))).sub_id);
    expect(subjects).toEqual([{ user: { user_id: id } }, { user: { user_id: id } }, { group: { group_id: "group-target" } }, { group: { group_id: "group-target" } }]);
  } finally { globalThis.fetch = original; }
});
