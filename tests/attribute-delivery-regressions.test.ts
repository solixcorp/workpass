import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { ensureApplicationTables } from "../src/db/schema";
import type { Env } from "../src/env";
import { inboundScimRoutes } from "../src/scim/server";
import { dispatchPendingScimOperations, scheduleScimAttributeSync } from "../src/scim/executor";
import { createScimOperation } from "../src/scim/operations";
import { ATTRIBUTE_CHANGED_EVENT_TYPE, emitAttributeChangedEvent } from "../src/ssf/attribute-events";
import { attemptPendingSSFDispatch, dispatchSSFEvent, SSF_DELIVERY_LEASE_MS, upsertSsfRecipient } from "../src/ssf/dispatch";
import { createTestD1 } from "./test-d1";

const urn = "urn:solixcorp:scim:1.0:CustomAttributes";
const bearer = "inbound-scim-token-0123456789abcdef-0123456789";
const envFor = (db: D1Database) => ({ DB: db, AUTH_BASE_URL: "https://auth.example.test", ENABLE_SSF_SENDER: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))), ENABLE_INBOUND_SCIM: "true", INBOUND_SCIM_BEARER_TOKEN: bearer, ENABLE_SCIM_PROVISIONING: "true", ENABLE_SCIM_ATTRIBUTE_RELEASE: "true", SCIM_TARGET_ID: "target", SCIM_BASE_URL: "https://scim.example.test", SCIM_BEARER_TOKEN: "secret" }) as unknown as Env;
const subject = (token: string) => JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))).sub_id;
async function recipient(env: Env) {
  await upsertSsfRecipient(env, { id: "r", audience: "aud", endpoint: "https://recipient.test/set", eventTypes: [ATTRIBUTE_CHANGED_EVENT_TYPE] });
}

describe("attribute delivery regressions", () => {
  test("SCIM create, changed PUT and PATCH identify the target; no-op writes do not emit", async () => {
    const { db } = createTestD1();
    const env = envFor(db);
    await ensureApplicationTables(env);
    await db.prepare('CREATE TABLE "user" (id TEXT PRIMARY KEY, name TEXT, email TEXT, username TEXT, emailVerified INTEGER, createdAt TEXT, updatedAt TEXT, role TEXT, banned INTEGER)').run();
    await recipient(env);
    const app = new Hono<{ Bindings: Env }>().route("/", inboundScimRoutes);
    const original = globalThis.fetch;
    const tokens: string[] = [];
    globalThis.fetch = (async (_url, init) => { tokens.push(String(init?.body)); return new Response(null, { status: 202 }); }) as typeof fetch;
    try {
      const headers = { authorization: `Bearer ${bearer}`, "content-type": "application/json" };
      const call = (path: string, method: string, body: unknown) => app.request(path, { method, headers, body: JSON.stringify(body) }, env);
      const create = await call("/scim/v2/Users", "POST", { userName: "user@example.test", name: { formatted: "User" }, [urn]: { a: 1 } });
      expect(create.status).toBe(201);
      const id = (await create.json() as { id: string }).id;
      const path = `/scim/v2/Users/${id}`;
      expect((await call(path, "PUT", { [urn]: { a: 2 } })).status).toBe(200);
      expect((await call(path, "PUT", { [urn]: { a: 2 } })).status).toBe(200);
      expect((await call(path, "PATCH", { Operations: [{ op: "replace", path: urn, value: { b: 3 } }] })).status).toBe(200);
      expect((await call(path, "PATCH", { Operations: [{ op: "replace", path: urn, value: { b: 3 } }] })).status).toBe(200);
      expect(tokens.map(subject)).toEqual(Array(3).fill({ user: { user_id: id } }));
    } finally { globalThis.fetch = original; }
  });

  test("subject uses the affected object rather than an administrator for each type", async () => {
    const env = envFor(createTestD1().db);
    await recipient(env);
    const tokens: string[] = [];
    const send = (async (_url, init) => { tokens.push(String(init?.body)); return new Response(null, { status: 202 }); }) as typeof fetch;
    for (const objectType of ["user", "group", "account"] as const) {
      await emitAttributeChangedEvent(env, { userId: "admin", objectType, objectId: "target", changedKeys: [] }, send);
    }
    expect(tokens.map(subject)).toEqual([{ user: { user_id: "target" } }, { group: { group_id: "target" } }, { account: { account_id: "target" } }]);
  });

  test("persisted pending rows recover after a crash and concurrent retries claim only once", async () => {
    const { db } = createTestD1();
    const env = envFor(db);
    await recipient(env);
    const originalPrepare = db.prepare.bind(db);
    let crash = true;
    db.prepare = ((sql: string) => {
      const stmt = originalPrepare(sql);
      if (!sql.includes("INSERT INTO ssf_deliveries")) return stmt;
      const bind = stmt.bind.bind(stmt);
      stmt.bind = ((...args: unknown[]) => {
        const bound = bind(...args);
        const run = bound.run.bind(bound);
        bound.run = (async () => { const result = await run(); if (crash) { crash = false; throw new Error("crash"); } return result; }) as typeof bound.run;
        return bound;
      }) as typeof stmt.bind;
      return stmt;
    }) as typeof db.prepare;
    let sends = 0;
    const send = (async () => { sends++; return new Response(null, { status: 202 }); }) as typeof fetch;
    await expect(dispatchSSFEvent(env, { recipientId: "r", eventType: ATTRIBUTE_CHANGED_EVENT_TYPE, subject: {} }, send)).rejects.toThrow("crash");
    expect(sends).toBe(0);
    const pending = await db.prepare("SELECT state, attempts, next_attempt_at FROM ssf_deliveries").first<{ state: string; attempts: number; next_attempt_at: number }>();
    expect(pending).toMatchObject({ state: "pending", attempts: 0 });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = send;
    try {
      await attemptPendingSSFDispatch(env, pending!.next_attempt_at - 1);
      expect(sends).toBe(0);
      await Promise.all([attemptPendingSSFDispatch(env, pending!.next_attempt_at + SSF_DELIVERY_LEASE_MS), attemptPendingSSFDispatch(env, pending!.next_attempt_at + SSF_DELIVERY_LEASE_MS)]);
      expect(sends).toBe(1);
      expect(await db.prepare("SELECT state, attempts FROM ssf_deliveries").first()).toEqual({ state: "delivered", attempts: 1 });
      expect((await dispatchSSFEvent(env, { recipientId: "r", eventType: ATTRIBUTE_CHANGED_EVENT_TYPE, subject: {} }, send)).state).toBe("delivered");
    } finally { globalThis.fetch = originalFetch; }
  });

  test("unmapped and locked sync skips are audited with reasons", async () => {
    const { db } = createTestD1();
    const env = envFor(db);
    await ensureApplicationTables(env);
    expect(await scheduleScimAttributeSync(env, "unmapped")).toBe(false);
    await db.prepare("INSERT INTO scim_user_mappings (target_id, user_id, external_user_id, created_at) VALUES (?, ?, ?, ?)").bind("target", "locked", "remote", new Date().toISOString()).run();
    expect(await createScimOperation(env, { targetId: "target", userId: "locked", operation: "update" })).not.toBeNull();
    expect(await scheduleScimAttributeSync(env, "locked")).toBe(false);
    const rows = await db.prepare("SELECT target_user_id, event_context FROM audit_events WHERE event_type = 'scim.operation.skipped' ORDER BY log_pos").all<{ target_user_id: string; event_context: string }>();
    expect(rows.results.map((row) => [row.target_user_id, JSON.parse(row.event_context).reason])).toEqual([["unmapped", "사용자 매핑 없음"], ["locked", "진행 중인 작업 있음"]]);
  });

  test("SCIM drain takes the oldest operations first and reports the backlog", async () => {
    const { db } = createTestD1();
    const env = envFor(db);
    await ensureApplicationTables(env);
    for (const [id, time] of [["new", "2026-02-01"], ["old", "2026-01-01"], ["middle", "2026-01-15"]]) {
      await db.prepare("INSERT INTO scim_operations (id, target_id, user_id, operation, status, created_at, updated_at) VALUES (?, 'target', ?, 'update', 'pending', ?, ?)").bind(id, id, time, time).run();
    }
    const original = console.info;
    const logs: unknown[][] = [];
    console.info = (...args: unknown[]) => { logs.push(args); };
    try { await dispatchPendingScimOperations(env, 2); } finally { console.info = original; }
    const rows = await db.prepare("SELECT id, status FROM scim_operations ORDER BY created_at").all<{ id: string; status: string }>();
    expect(rows.results).toEqual([{ id: "old", status: "failed" }, { id: "middle", status: "failed" }, { id: "new", status: "pending" }]);
    expect(logs).toEqual([["SCIM pending operations", { processed: 2, remaining: 1 }]]);
  });
});
