import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { auditRequestContext } from "../../src/audit/request-context";
import { insertAuditEvent, verifyAuditEventChain } from "../../src/audit/store";
import { compileAuditQuery } from "../../src/audit/query";

const ORIGIN = "http://127.0.0.1:8787";
describe("audit query and request context", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "detail-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))) } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";
  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string>; cf?: Record<string, unknown>; anonymous?: boolean }) {
    const headers: Record<string, string> = { ...init?.headers };
    if (jar.size && !init?.anonymous) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const req = new Request(`${ORIGIN}${path}`, { method: init?.method ?? "GET", headers, body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
    if (init?.cf) Object.defineProperty(req, "cf", { value: init.cf });
    const response = await mod.fetch(req, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) { const [pair] = cookie.split(";"); const i = pair!.indexOf("="); if (i > 0) jar.set(pair!.slice(0, i), pair!.slice(i + 1)); }
    return response;
  }
  const json = async (r: Response): Promise<any> => r.json();
  const search = async (q: string, extra = "") => call(`/api/admin/audit-events?page=1&limit=100&query=${encodeURIComponent(q)}${extra}`);
  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` }, body: { email: "admin@detail.test", name: "Admin Kim", username: "detadmin", password: "Detail-7d9Kpw9zL2xQ" } }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "detadmin", password: "Detail-7d9Kpw9zL2xQ" } })).status).toBe(200);
    await insertAuditEvent(env, { id: "old-test", actor_user_id: null, target_user_id: adminId, event_type: "test.old", outcome: "failure", request_path: "/old" });
    const created = await call("/api/admin/directory-groups", { method: "POST", body: { name: "geo-test", description: "" }, headers: { "cf-connecting-ip": "203.0.113.10" }, cf: { country: "KR", region: "Seoul", city: "Seoul", asn: 1234, timezone: "Asia/Seoul", latitude: "37" } });
    expect(created.status).toBe(201);
    await auditRequestContext.run({ ip: "203.0.113.11", geo: { country: "KR", region: "Seoul", city: "Seoul", asn: "1234", timezone: null } }, () => insertAuditEvent(env, { id: "explicit-test", actor_user_id: adminId, target_user_id: null, event_type: "test.explicit", outcome: "failure", request_path: "/test", client_ip: "198.51.100.1", event_context: { data: "50%_safe" } }));
  });
  test("request capture, old rows, explicit IP and chain", async () => {
    const row = await db.prepare("SELECT client_ip,event_context FROM audit_events WHERE client_ip = ? LIMIT 1").bind("203.0.113.10").first<any>();
    expect(row).toBeTruthy(); expect(JSON.parse(row.event_context).geo).toEqual({ country: "KR", region: "Seoul", city: "Seoul", asn: "1234", timezone: "Asia/Seoul" });
    const old = (await json(await call("/api/admin/audit-events/old-test"))).event;
    expect(old).toMatchObject({ client_ip: null, client_geo: null });
    const explicit = (await json(await call("/api/admin/audit-events/explicit-test"))).event;
    expect(explicit).toMatchObject({ client_ip: "198.51.100.1", client_geo: { country: "KR", city: "Seoul", region: "Seoul", asn: "1234" } });
    expect((await verifyAuditEventChain(env)).verified).toBe(true);
  });
  test("concurrent contexts remain isolated across awaits", async () => {
    await Promise.all(["a", "b"].map((id) => auditRequestContext.run({ ip: id, geo: null }, async () => {
      await new Promise((resolve) => setTimeout(resolve, id === "a" ? 10 : 1));
      await insertAuditEvent(env, { id: `parallel-${id}`, actor_user_id: null, target_user_id: null, event_type: "test.parallel", outcome: "failure", request_path: "/" });
    })));
    const rows = await db.prepare("SELECT id, client_ip FROM audit_events WHERE event_type = 'test.parallel' ORDER BY id").all<any>();
    expect(rows.results).toEqual([{ id: "parallel-a", client_ip: "a" }, { id: "parallel-b", client_ip: "b" }]);
  });
  test("concurrent HTTP requests retain their own addresses and locations", async () => {
    const requests = [
      { id: "first", ip: "192.0.2.11", city: "Seoul" },
      { id: "second", ip: "192.0.2.12", city: "Busan" },
    ];
    const responses = await Promise.all(requests.map(async (item) => {
      await Promise.resolve();
      return call("/api/admin/directory-groups", { method: "POST", body: { name: `parallel-${item.id}`, description: "" }, headers: { "cf-connecting-ip": item.ip }, cf: { country: "KR", city: item.city } });
    }));
    expect(responses.map((r) => r.status)).toEqual([201, 201]);
    for (const item of requests) {
      const rows = await db.prepare("SELECT event_context FROM audit_events WHERE client_ip = ?").bind(item.ip).all<any>();
      expect(rows.results.length).toBeGreaterThan(0);
      expect(rows.results.every((r: any) => JSON.parse(r.event_context).geo.city === item.city)).toBe(true);
    }
  });
  test("fields, aliases, operators, people and geo", async () => {
    for (const q of [
      'id = "explicit-test"', 'type = "test.explicit"', 'outcome = "failure"', 'ip startswith "198.51.100."', 'path endswith "test"',
      'time >= "-24h"', `actor = "${adminId}"`, 'actor = "admin@detail.test"', 'actor = "Admin Kim"', 'actor ~ "kim"',
      'actor.email = "admin@detail.test"', 'actor.name ~ "kim"', 'user = "Admin Kim"', 'country = "KR"', 'city = "Seoul"',
      'region = "Seoul"', 'asn = "1234"', 'context ~ "50%_safe"', 'type in ("test.explicit", "other")',
      'type not in ("other")', 'type != "other"', 'type !~ "other"', 'type not startswith "other"', 'type not endswith "other"',
      '(type = "test.explicit" or type = "other") and time < "2100-01-01"', 'type >= "test"', 'type > "aaa"', 'type <= "zzz"', 'type < "zzz"',
    ]) {
      const response = await search(`${q} and id = "explicit-test"`);
      expect(response.status).toBe(200);
      expect((await json(response)).total).toBe(1);
    }
    for (const q of ['actor = None', `target = "${adminId}"`, 'target.email = "admin@detail.test"', 'target.name = "Admin Kim"', 'user = "Admin Kim"']) {
      expect((await json(await search(`${q} and id = "old-test"`))).total).toBe(1);
    }
    expect((await json(await search('actor != None and id = "explicit-test"'))).total).toBe(1);
  });
  test("filtering precedes pagination and other filters", async () => {
    const q = 'type startswith "test." and outcome = "failure"';
    const first = await json(await call(`/api/admin/audit-events?page=1&limit=1&query=${encodeURIComponent(q)}&eventPrefix=test.&outcome=failure&from=2000-01-01T00%3A00%3A00Z&to=2100-01-01T00%3A00%3A00Z`));
    expect(first.total).toBeGreaterThanOrEqual(4); expect(first.events.length).toBe(1);
    const second = await json(await call(`/api/admin/audit-events?page=2&limit=1&query=${encodeURIComponent(q)}&eventPrefix=test.&outcome=failure&from=2000-01-01T00%3A00%3A00Z&to=2100-01-01T00%3A00%3A00Z`));
    expect(second.total).toBe(first.total); expect(second.events[0].id).not.toBe(first.events[0].id);
    const cursor = await json(await call(`/api/admin/audit-events?limit=1&query=${encodeURIComponent(q)}&cursor=${first.events[0].id}`));
    expect(cursor.events[0].id).not.toBe(first.events[0].id);
    const geo = await json(await call("/api/admin/audit-events?page=1&country=KR&ip=198.51.100.1"));
    expect(geo.total).toBe(1);
  });
  test("invalid and injection inputs, complexity and help", async () => {
    for (const q of ['badfield = "x"', 'id = "unterminated', 'id = "x" garbage', 'id; DROP TABLE audit_events', Array(30).fill('id = "x"').join(" or "), `id in (${Array(51).fill('"x"').join(",")})`]) {
      const response = await search(q); expect(response.status).toBe(400);
      const body = await json(response); expect(typeof body.error).toBe("string"); expect("position" in body).toBe(true); expect(typeof body.detail).toBe("string");
    }
    expect((await json(await search('id = "x\' OR 1=1 --"'))).total).toBe(0);
    const help = await json(await call("/api/admin/audit-events/fields")); expect(help.fields.length).toBeGreaterThan(10); expect(help.examples.length).toBeGreaterThanOrEqual(8);
    expect((await call("/api/admin/audit-events/fields", { anonymous: true })).status).toBe(401);
    expect((await call("/api/admin/audit-events", { anonymous: true })).status).toBe(401);
    expect(() => compileAuditQuery('id = "x" extra')).toThrow();
  });
});
