import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** An administrator reads what a user allowed, when, and the device verdict at that moment. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Activity-7d9Kpw9zL2";
const CALLBACK = "https://wiki.example.com/callback";

describe("app activity of a user", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
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
    const boot = await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@activity.test", name: "Admin", username: "actadmin", password: PASSWORD },
    }));
    adminId = boot.user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "actadmin", password: PASSWORD } })).status).toBe(200);
    const created = await json(await call("/api/admin/oidc-clients", { method: "POST", body: {
      name: "Wiki", applicationType: "web", redirectUris: [CALLBACK],
    } }));
    clientId = created.client.clientId;
    await call("/api/admin/applications", { method: "POST", body: { slug: "wiki", name: "Wiki", protocol: "oidc", binding: clientId } });
    expect((await call("/api/admin/applications/wiki/enable", { method: "POST" })).status).toBe(200);
  });

  test("allowing an app and signing in again are recorded with the verdict that was current", async () => {
    expect(await json(await call(`/api/admin/users/${adminId}/app-activity`))).toMatchObject({ apps: [], events: [] });

    // The first request goes to the consent page; allowing it hands out the code.
    const authorize = await call(authorizePath());
    expect(authorize.status).toBe(302);
    const consentUrl = new URL(authorize.headers.get("location")!, ORIGIN);
    expect(consentUrl.pathname).toBe("/consent");
    const consent = await call("/api/auth/oauth2/consent", { method: "POST", body: {
      oauth_query: consentUrl.search.slice(1), accept: true, scopes: ["openid", "profile", "email"],
    } });
    expect(consent.status).toBe(200);

    let view = await json(await call(`/api/admin/users/${adminId}/app-activity`));
    expect(view.events).toHaveLength(1);
    expect(view.events[0]).toMatchObject({ kind: "consent", scopes: ["openid", "profile", "email"], risk: null, app: { name: "Wiki", slug: "wiki" } });
    expect(view.apps[0]).toMatchObject({ name: "Wiki", signIns: 1, consent: { scopes: expect.arrayContaining(["openid", "profile"]) } });

    // A device verdict for this app, then a second sign-in: the verdict is copied in.
    await db.prepare(
      `INSERT INTO fingerprint_risk_decisions (id, user_id, event_id, action, reasons, request_path, occurred_at, subject)
       VALUES ('d-app', ?, 'evt', 'step_up', '["untrusted_device","rapid_network_change"]', '/api/auth/oauth2/authorize', ?, ?)`,
    ).bind(adminId, new Date().toISOString(), `oidc:${clientId}`).run();
    const again = await call(authorizePath());
    expect(again.status).toBe(302);
    expect(again.headers.get("location")).toContain("code=");

    view = await json(await call(`/api/admin/users/${adminId}/app-activity`));
    expect(view.events).toHaveLength(2);
    expect(view.events[0]).toMatchObject({ kind: "sign_in", risk: { action: "step_up", reasons: ["untrusted_device", "rapid_network_change"], scope: "app" } });
    expect(view.apps[0].signIns).toBe(2);
    expect(view.apps[0].lastRisk.action).toBe("step_up");

    // A refused consent records nothing.
    await db.prepare('DELETE FROM "oauthConsent"').run();
    const second = await call(authorizePath());
    const again2 = new URL(second.headers.get("location")!, ORIGIN);
    expect(again2.pathname).toBe("/consent");
    await call("/api/auth/oauth2/consent", { method: "POST", body: { oauth_query: again2.search.slice(1), accept: false } });
    expect((await json(await call(`/api/admin/users/${adminId}/app-activity`))).events).toHaveLength(2);
  });

  test("only administrators can read it, and an unknown user is a 404", async () => {
    expect((await call("/api/admin/users/nobody/app-activity")).status).toBe(404);
    const anonymous = await mod.fetch(new Request(`${ORIGIN}/api/admin/users/${adminId}/app-activity`), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect(anonymous.status).toBe(401);
  });
});
