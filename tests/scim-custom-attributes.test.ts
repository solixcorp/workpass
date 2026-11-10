import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { ensureApplicationTables } from "../src/db/schema";
import { inboundScimRoutes } from "../src/scim/server";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

const BEARER = "inbound-scim-token-0123456789abcdef-0123456789";
const URN = "urn:solixcorp:scim:1.0:CustomAttributes";
const AUTH = { authorization: `Bearer ${BEARER}`, "content-type": "application/json" };

async function app(): Promise<{ request: (path: string, init?: RequestInit) => Promise<Response>; env: Env }> {
  const testD1 = createTestD1();
  const env = {
    DB: testD1.db,
    ENABLE_INBOUND_SCIM: "true",
    INBOUND_SCIM_BEARER_TOKEN: BEARER,
  } as unknown as Env;
  await ensureApplicationTables(env);
  await testD1.sqlite.exec(
    `CREATE TABLE IF NOT EXISTS "user" (
      id TEXT PRIMARY KEY NOT NULL, name TEXT, email TEXT, username TEXT,
      emailVerified INTEGER, createdAt TEXT, updatedAt TEXT, role TEXT, banned INTEGER)`,
  );
  const hono = new Hono<{ Bindings: Env }>();
  hono.route("/", inboundScimRoutes);
  return {
    env,
    request: (path, init) => hono.request(`http://localhost${path}`, init, env),
  };
}

async function createUser(request: (path: string, init?: RequestInit) => Promise<Response>, extra: Record<string, unknown> = {}): Promise<{ id: string; body: Record<string, unknown> }> {
  const response = await request("/scim/v2/Users", {
    method: "POST",
    headers: AUTH,
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "scim@example.test",
      name: { formatted: "Scim User" },
      emails: [{ value: "scim@example.test", primary: true }],
      ...extra,
    }),
  });
  const body = await response.json() as Record<string, unknown>;
  return { id: String(body.id ?? ""), body };
}

describe("SCIM custom attributes", () => {
  test("creation with the extension stores and echoes validated attributes", async () => {
    const { request } = await app();
    const created = await createUser(request, {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", URN],
      [URN]: { employeeType: "contractor", badgeNumber: 4711 },
    });
    expect(created.id.length > 0).toBe(true);
    expect((created.body[URN] as Record<string, unknown>)).toEqual({ employeeType: "contractor", badgeNumber: 4711 });
    // The extension is advertised in schemas only when attributes exist.
    expect((created.body.schemas as string[]).includes(URN)).toBe(true);
  });

  test("an invalid attribute payload is a SCIM 400 with no user created", async () => {
    const { request, env } = await app();
    const before = await env.DB.prepare("SELECT COUNT(*) AS count FROM \"user\"").first<{ count: number }>();
    const response = await request("/scim/v2/Users", {
      method: "POST",
      headers: AUTH,
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", URN],
        userName: "bad@example.test",
        name: { formatted: "Bad" },
        [URN]: { nested: { object: true } },
      }),
    });
    expect(response.status).toBe(400);
    const after = await env.DB.prepare("SELECT COUNT(*) AS count FROM \"user\"").first<{ count: number }>();
    expect(after?.count).toBe(before?.count);
  });

  test("PUT replaces the set and GET returns it; an empty extension clears it", async () => {
    const { request } = await app();
    const created = await createUser(request);
    await request(`/scim/v2/Users/${created.id}`, {
      method: "PUT",
      headers: AUTH,
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", URN],
        userName: "scim@example.test",
        name: { formatted: "Scim User" },
        active: true,
        [URN]: { team: "runtime", level: 3 },
      }),
    });
    let fetched = await (await request(`/scim/v2/Users/${created.id}`, { headers: AUTH })).json() as Record<string, unknown>;
    expect(fetched[URN]).toEqual({ team: "runtime", level: 3 });

    await request(`/scim/v2/Users/${created.id}`, {
      method: "PUT",
      headers: AUTH,
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", URN],
        userName: "scim@example.test",
        name: { formatted: "Scim User" },
        active: true,
        [URN]: {},
      }),
    });
    fetched = await (await request(`/scim/v2/Users/${created.id}`, { headers: AUTH })).json() as Record<string, unknown>;
    expect(fetched[URN]).toBeUndefined();
  });

  test("PATCH supports replacing and removing the extension", async () => {
    const { request } = await app();
    const created = await createUser(request, {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", URN],
      [URN]: { team: "core" },
    });
    await request(`/scim/v2/Users/${created.id}`, {
      method: "PATCH",
      headers: AUTH,
      body: JSON.stringify({ Operations: [{ op: "replace", path: URN, value: { team: "runtime" } }] }),
    });
    let fetched = await (await request(`/scim/v2/Users/${created.id}`, { headers: AUTH })).json() as Record<string, unknown>;
    expect(fetched[URN]).toEqual({ team: "runtime" });
    await request(`/scim/v2/Users/${created.id}`, {
      method: "PATCH",
      headers: AUTH,
      body: JSON.stringify({ Operations: [{ op: "remove", path: URN }] }),
    });
    fetched = await (await request(`/scim/v2/Users/${created.id}`, { headers: AUTH })).json() as Record<string, unknown>;
    expect(fetched[URN]).toBeUndefined();
  });
});
