import { beforeAll, describe, expect, test } from "bun:test";
import worker from "../src/index";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";
import { createScimOperation, expireScimLeases } from "../src/scim/operations";
import { executeScimOperation } from "../src/scim/executor";

describe("SCIM lease reconciliation", () => {
  const { db } = createTestD1();
  const origin = "http://127.0.0.1:8787";
  const env = { DB: db, AUTH_BASE_URL: origin, AUTH_SECRET: "integration-secret-0123456789abcdef", ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-012345", ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-012345", ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true" } as unknown as Env;
  const jar = new Map<string, string>(); let userId = "";
  async function call(path: string, method = "GET", body?: unknown, auth = true) {
    const headers: Record<string, string> = { Origin: origin };
    if (auth && jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (path === "/_internal/migrate") headers.Authorization = `Bearer ${env.MIGRATION_TOKEN}`;
    if (path === "/api/admin/bootstrap") headers.Authorization = `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}`;
    const response = await worker.fetch(new Request(origin + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, {} as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) { const p = cookie.split(";")[0]!; const i = p.indexOf("="); if (i > 0) jar.set(p.slice(0, i), p.slice(i + 1)); }
    return response;
  }
  beforeAll(async () => {
    expect((await call("/_internal/migrate", "POST")).status).toBe(200);
    const boot = await call("/api/admin/bootstrap", "POST", { username: "leaseadmin", email: "admin@lease.test", name: "Lease Admin", password: "LeaseOnly-7d9Kpw9zL2" });
    userId = ((await boot.json()) as any).user.id;
    expect((await call("/api/auth/sign-in/username", "POST", { username: "leaseadmin", password: "LeaseOnly-7d9Kpw9zL2" })).status).toBe(200);
  });
  test("stale leases become unknown while fresh and pending remain untouched", async () => {
    const old = new Date(Date.now() - 11 * 60_000).toISOString(); const now = new Date().toISOString();
    for (const [id, target, status, updated] of [["stale", "target", "in_progress", old], ["fresh", "fresh-target", "in_progress", now], ["pending", "pending-target", "pending", old]]) await db.prepare("INSERT INTO scim_operations (id,target_id,user_id,operation,status,created_at,updated_at) VALUES (?,?,?,'create',?,?,?)").bind(id, target, userId, status, old, updated).run();
    expect(await createScimOperation(env, { targetId: "target", userId, operation: "create" })).toBeNull();
    await expireScimLeases(env);
    const rows = await db.prepare("SELECT id,status,abandoned FROM scim_operations ORDER BY id").all();
    expect(rows.results).toEqual([{ id: "fresh", status: "in_progress", abandoned: 0 }, { id: "pending", status: "pending", abandoned: 0 }, { id: "stale", status: "outcome_unknown", abandoned: 1 }]);
    const list = await (await call("/api/admin/scim-operations")).json() as any;
    expect(list.operations.find((o: any) => o.id === "stale")).toMatchObject({ abandoned: true, resolved_at: null, resolved_by_name: null, resolution_note: null });
  });
  test("resolve releases the slot and records the administrator", async () => {
    const path = "/api/admin/scim-operations/stale/resolve";
    expect((await call(path, "POST", {}, false)).status).toBe(401);
    expect((await call("/api/admin/scim-operations/fresh/resolve", "POST", {})).status).toBe(409);
    const response = await call(path, "POST", { note: "Checked remote system" }); expect(response.status).toBe(200); expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toMatchObject({ operation: { id: "stale", status: "failed", abandoned: true, resolved_by_name: "Lease Admin", resolution_note: "Checked remote system" } });
    expect((await call(path, "POST", {})).status).toBe(409);
    const id = await createScimOperation(env, { targetId: "target", userId, operation: "create" }); expect(id).not.toBeNull();
    const original = globalThis.fetch;
    try {
      globalThis.fetch = (async () => Response.json({ id: "remote-user" }, { status: 201 })) as typeof fetch;
      expect(await executeScimOperation(env, { targetId: "target", target: { baseUrl: "https://scim.example.test", bearerToken: "token" } }, id!)).toBe(true);
    } finally { globalThis.fetch = original; }
    const events = await db.prepare("SELECT event_type, outcome FROM audit_events WHERE event_type LIKE 'scim.operation.%'").all();
    expect(events.results).toEqual(expect.arrayContaining([{ event_type: "scim.operation.lease_expired", outcome: "success" }, { event_type: "scim.operation.resolve", outcome: "success" }]));
  });
});
