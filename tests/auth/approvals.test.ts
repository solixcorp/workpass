import { beforeAll, describe, expect, test } from "bun:test";
import { createCibaRequest } from "../../src/oauth/ciba";
import { createDeviceGrant } from "../../src/oauth/device-flow";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** An administrator reads what a user allowed, when, and the device verdict at that moment. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Activity-7d9Kpw9zL2";
const CALLBACK = "https://wiki.example.com/callback";

describe("approval pages data", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", ENABLE_DEVICE_FLOW: "true", ENABLE_CIBA: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";
  let clientId = "";

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

  const authorizePath = () => `/api/auth/oauth2/authorize?${new URLSearchParams({
    client_id: clientId, redirect_uri: CALLBACK, response_type: "code", scope: "openid profile email",
    state: "s", code_challenge: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", code_challenge_method: "S256",
  })}`;

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@approvals.test", name: "Admin", username: "apradmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "apradmin", password: PASSWORD } })).status).toBe(200);
    const created = await json(await call("/api/admin/oidc-clients", { method: "POST", body: { name: "Wiki", applicationType: "web", redirectUris: [CALLBACK] } }));
    clientId = created.client.clientId;
    await call("/api/admin/applications", { method: "POST", body: { slug: "wiki", name: "Wiki", protocol: "oidc", binding: clientId } });
  });

  const query = (scope: string) => `/api/consent/context?${new URLSearchParams({ client_id: clientId, scope })}`;

  test("the consent page needs a session, then says who asks for what and whether this person may continue", async () => {
    const saved = new Map(jar);
    jar.clear();
    expect((await call(query("openid"))).status).toBe(401);
    for (const [key, value] of saved) jar.set(key, value);

    // A hostile scope is data in JSON, never markup.
    const hostile = "</script><script>alert(1)</script>";
    const view = await json(await call(query(`openid ${hostile}`)));
    expect(view).toMatchObject({ allowed: true, application: { name: "Wiki" }, account: { email: "admin@approvals.test" } });
    expect(view.scopes).toEqual(["openid", hostile]);

    const sales = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "sales", description: "" } }))).group;
    await call("/api/admin/applications/wiki/assignment", { method: "PUT", body: { mode: "groups", groups: [sales.id] } });
    expect((await json(await call(query("openid")))).allowed).toBe(false);
    expect((await call("/api/consent/context")).status).toBe(400);
  });

  test("a device code is looked up, then approved or denied once", async () => {
    const post = (path: string, body: unknown) => call(path, { method: "POST", body });
    expect((await post("/api/device/flow/verify", { user_code: "NOPE-NOPE" })).status).toBe(404);

    const first = await createDeviceGrant(env, clientId, ["openid", "email"]);
    const seen = await json(await post("/api/device/flow/verify", { user_code: first.userCode }));
    expect(seen).toMatchObject({ client_name: "Wiki", scopes: ["openid", "email"] });
    expect((await json(await post("/api/device/flow/deny", { user_code: first.userCode })))).toEqual({ status: "denied" });
    expect((await post("/api/device/flow/approve", { user_code: first.userCode })).status).toBe(409);

    const second = await createDeviceGrant(env, clientId, ["openid"]);
    // Assignment still restricts the app to the sales group, so this admin (not in
    // sales) is denied at approval by the OIDC access gate — and the grant survives.
    expect((await json(await post("/api/device/flow/approve", { user_code: second.userCode })))).toEqual({ error: "access_denied" });
    await call("/api/admin/applications/wiki/assignment", { method: "PUT", body: { mode: "everyone" } });
    expect((await json(await post("/api/device/flow/approve", { user_code: second.userCode })))).toEqual({ status: "approved" });
  });

  test("pending sign-in requests are listed for their user and decided from the page", async () => {
    await createCibaRequest(env, { clientId, userId: adminId, scopes: ["openid"], bindingMessage: "코드 4821" });
    const pending = await json(await call("/api/ciba/pending"));
    expect(pending.requests).toHaveLength(1);
    expect(pending.requests[0]).toMatchObject({ clientName: "Wiki", scopes: ["openid"], bindingMessage: "코드 4821" });

    const decided = await call("/api/ciba/decide", { method: "POST", body: { request: pending.requests[0].id, decision: "approve" } });
    expect(await json(decided)).toEqual({ status: "approved" });
    expect((await json(await call("/api/ciba/pending"))).requests).toHaveLength(0);
    expect((await call("/api/ciba/decide", { method: "POST", body: { request: pending.requests[0].id, decision: "deny" } })).status).toBe(409);
    expect((await call("/api/ciba/decide", { method: "POST", body: { request: "x", decision: "maybe" } })).status).toBe(400);
  });

  test("none of it is open without a session", async () => {
    jar.clear();
    expect((await call("/api/ciba/pending")).status).toBe(401);
    expect((await call("/api/device/flow/verify", { method: "POST", body: { user_code: "AAAA-BBBB" } })).status).toBe(401);
    expect((await call("/api/ciba/decide", { method: "POST", body: { request: "x", decision: "approve" } })).status).toBe(401);
  });
});
