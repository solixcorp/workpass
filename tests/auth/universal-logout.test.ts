import { beforeAll, describe, expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { jwtVerify } from "../oidc/oidc-crypto";

describe("universal app logout", () => {
  const { db, sqlite } = createTestD1();
  const origin = "http://127.0.0.1:8787";
  const uri = "https://rp.example.test/logout";
  const env = { DB: db, AUTH_BASE_URL: origin, AUTH_SECRET: "integration-secret-0123456789abcdef",
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-012345",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-012345",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true" } as unknown as Env;
  const cookies = new Map<string, string>();
  let userId = "";
  let clientId = "";
  async function call(path: string, init: { method?: string; body?: unknown; headers?: Record<string, string> } = {}) {
    const headers: Record<string, string> = { Origin: origin, ...init.headers };
    if (cookies.size) headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await worker.fetch(new Request(origin + path, { method: init.method ?? "GET", headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body) }), env, {} as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const at = pair.indexOf("=");
      if (at > 0) cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return response;
  }
  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    sqlite.query("INSERT INTO oidc_logout_uri_approvals VALUES (?)").run(uri);
    const boot = await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { username: "logoutadmin", email: "admin@logout.test", name: "Admin", password: "LogoutOnly-7d9Kpw9zL2" } });
    userId = ((await boot.json()) as any).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "logoutadmin", password: "LogoutOnly-7d9Kpw9zL2" } })).status).toBe(200);
    const created = await call("/api/admin/oidc-clients", { method: "POST", body: { name: "Logout RP", applicationType: "web", redirectUris: ["https://rp.example.test/callback"], backchannelLogoutUri: uri } });
    expect(created.status).toBe(201);
    clientId = ((await created.json()) as any).client.clientId;
  });
  test("validates backchannel endpoints", async () => {
    for (const url of ["http://example.com/logout", "https://127.0.0.1/logout", "https://192.168.1.3/logout", "https://[::1]/logout"]) {
      expect((await call(`/api/admin/oidc-clients/${clientId}`, { method: "PATCH", body: { backchannelLogoutUri: url } })).status).toBe(400);
    }
    expect(((await (await call(`/api/admin/oidc-clients/${clientId}`)).json()) as any).client.backchannelLogoutUri).toBe(uri);
  });
  test("lists, revokes and signs logout tokens and self-disconnect removes consent", async () => {
    const now = Date.now();
    await db.prepare('INSERT INTO "oauthAccessToken" (id, token, clientId, userId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind("at-universal", "token-universal", clientId, userId, now + 3600000, now, '["openid"]').run();
    await db.prepare('INSERT INTO "oauthConsent" (id, clientId, userId, scopes, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)')
      .bind("consent-universal", clientId, userId, '["openid"]', now, now).run();
    const list = await (await call(`/api/admin/users/${userId}/app-sessions`)).json() as any;
    expect(list.apps[0]).toMatchObject({ clientId, slug: null, applicationName: "Logout RP", activeTokens: 1, backchannelLogout: true });
    const originalFetch = globalThis.fetch;
    let logoutToken = "";
    try {
      globalThis.fetch = (async (_input, init) => {
        expect(init?.redirect).toBe("error");
        logoutToken = new URLSearchParams(String(init?.body)).get("logout_token") ?? "";
        return new Response(null, { status: 204 });
      }) as typeof fetch;
      const revoked = await call(`/api/admin/users/${userId}/app-sessions/revoke`, { method: "POST", body: { clientId } });
      expect(await revoked.json()).toMatchObject({ revokedTokens: 1, apps: [{ clientId, status: "sent", httpStatus: 204 }] });
    } finally { globalThis.fetch = originalFetch; }
    const jwks = await (await call("/api/auth/jwks")).json() as { keys: Array<{ kty?: string; x?: string; y?: string; kid?: string }> };
    const claims = await jwtVerify(logoutToken, jwks.keys) as Record<string, unknown>;
    expect(claims).toMatchObject({ iss: `${origin}/api/auth`, aud: clientId, sub: userId, events: { "http://schemas.openid.net/event/backchannel-logout": {} } });
    expect((await (await call("/api/me/connected-apps")).json() as any).apps[0]).toMatchObject({ clientId, activeTokens: 0, scopes: ["openid"] });
    try {
      globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
      const disconnected = await call(`/api/me/connected-apps/${clientId}`, { method: "DELETE" });
      expect(disconnected.status).toBe(200);
    } finally { globalThis.fetch = originalFetch; }
    expect(await db.prepare('SELECT id FROM "oauthConsent" WHERE userId = ? AND clientId = ?').bind(userId, clientId).first()).toBeNull();
    expect((await call(`/api/me/connected-apps/${clientId}`, { method: "DELETE" })).status).toBe(404);
  });
  test("requires authentication", async () => {
    const response = await worker.fetch(new Request(`${origin}/api/me/connected-apps`), env, {} as ExecutionContext);
    expect(response.status).toBe(401);
  });
  test("reports unsupported and failed app deliveries without blocking revocation", async () => {
    const noUri = await call("/api/admin/oidc-clients", { method: "POST", body: { name: "No logout", applicationType: "web", redirectUris: ["https://rp.example.test/callback"] } });
    const otherId = ((await noUri.json()) as any).client.clientId;
    const now = Date.now();
    for (const [id, client] of [["failure", clientId], ["unsupported", otherId]]) {
      await db.prepare('INSERT INTO "oauthAccessToken" (id, token, clientId, userId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(id, `token-${id}`, client, userId, now + 3600000, now, '["openid"]').run();
    }
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(null, { status: 503 })) as typeof fetch;
      const response = await call(`/api/admin/users/${userId}/app-sessions/revoke`, { method: "POST", body: {} });
      const result = await response.json() as any;
      expect(result.revokedTokens).toBe(2);
      expect(result.apps).toEqual(expect.arrayContaining([
        expect.objectContaining({ clientId, status: "failed", httpStatus: 503 }),
        expect.objectContaining({ clientId: otherId, status: "not_supported" }),
      ]));
    } finally { globalThis.fetch = originalFetch; }
  });
  test("session-required client receives the session identifier", async () => {
    expect((await call(`/api/admin/oidc-clients/${clientId}`, { method: "PATCH", body: { backchannel_logout_session_required: true } })).status).toBe(200);
    const devices = await (await call(`/api/admin/users/${userId}/devices`)).json() as any;
    const sid = devices.sessions.find((s: any) => s.current).id as string;
    const now = Date.now();
    await db.prepare('INSERT INTO "oauthAccessToken" (id, token, clientId, userId, sessionId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind("sid-token", "sid-token-value", clientId, userId, sid, now + 3600000, now, '["openid"]').run();
    const originalFetch = globalThis.fetch;
    let token = "";
    try {
      globalThis.fetch = (async (_input, init) => { token = new URLSearchParams(String(init?.body)).get("logout_token") ?? ""; return new Response(null, { status: 204 }); }) as typeof fetch;
      const result = await (await call(`/api/admin/users/${userId}/app-sessions/revoke`, { method: "POST", body: { clientId } })).json() as any;
      expect(result.apps[0].status).toBe("sent");
    } finally { globalThis.fetch = originalFetch; }
    const jwks = await (await call("/api/auth/jwks")).json() as { keys: Array<{ kty?: string; x?: string; y?: string; kid?: string }> };
    expect((await jwtVerify(token, jwks.keys) as Record<string, unknown>).sid).toBe(sid);
    expect((await call(`/api/admin/oidc-clients/${clientId}`, { method: "PATCH", body: { backchannelLogoutSessionRequired: false } })).status).toBe(200);
  });
  test("single-session revoke leaves app tokens alone; ban revokes and notifies", async () => {
    const created = await call("/api/admin/users", { method: "POST", body: { email: "other@logout.test", name: "Other", sendEmail: false } });
    const otherId = ((await created.json()) as any).user.id as string;
    const now = Date.now();
    await db.prepare('INSERT INTO "session" (id, expiresAt, token, createdAt, updatedAt, userId) VALUES (?, ?, ?, ?, ?, ?)')
      .bind("single-session", now + 3600000, "single-session-token", now, now, otherId).run();
    await db.prepare('INSERT INTO "oauthAccessToken" (id, token, clientId, userId, sessionId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind("ban-token", "ban-token-value", clientId, otherId, "single-session", now + 3600000, now, '["openid"]').run();
    expect((await call(`/api/admin/users/${otherId}/sessions/single-session`, { method: "DELETE" })).status).toBe(200);
    expect((await db.prepare('SELECT revoked FROM "oauthAccessToken" WHERE id = ?').bind("ban-token").first<{ revoked: number | null }>())?.revoked).toBeNull();
    const originalFetch = globalThis.fetch;
    let deliveries = 0;
    try {
      globalThis.fetch = (async () => { deliveries++; return new Response(null, { status: 204 }); }) as typeof fetch;
      expect((await call("/api/auth/admin/ban-user", { method: "POST", body: { userId: otherId } })).status).toBe(200);
    } finally { globalThis.fetch = originalFetch; }
    expect(deliveries).toBe(1);
    expect((await db.prepare('SELECT revoked FROM "oauthAccessToken" WHERE id = ?').bind("ban-token").first<{ revoked: number | null }>())?.revoked).not.toBeNull();
  });
  test("self all-sessions revokes offline refresh tokens even on delivery timeout", async () => {
    const now = Date.now();
    await db.prepare('INSERT INTO "oauthRefreshToken" (id, token, clientId, userId, expiresAt, createdAt, scopes, rotationReplayResponse, rotationReplayExpiresAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind("self-refresh", "self-refresh-value", clientId, userId, now + 3600000, now, '["openid","offline_access"]', "cached", now + 60000).run();
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => { throw new DOMException("Timed out", "TimeoutError"); }) as typeof fetch;
      expect((await call("/api/auth/revoke-sessions", { method: "POST", body: {} })).status).toBe(200);
    } finally { globalThis.fetch = originalFetch; }
    const token = await db.prepare('SELECT revoked, rotationReplayResponse FROM "oauthRefreshToken" WHERE id = ?').bind("self-refresh").first<{ revoked: number | null; rotationReplayResponse: string | null }>();
    expect(token?.revoked).not.toBeNull();
    expect(token?.rotationReplayResponse).toBeNull();
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "logoutadmin", password: "LogoutOnly-7d9Kpw9zL2" } })).status).toBe(200);
  });
  test("all-session revocation revokes issued app tokens", async () => {
    const now = Date.now();
    await db.prepare('INSERT INTO "oauthAccessToken" (id, token, clientId, userId, expiresAt, createdAt, scopes) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind("all-sessions", "token-all-sessions", clientId, userId, now + 3600000, now, '["openid"]').run();
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
      expect((await call("/api/auth/admin/revoke-user-sessions", { method: "POST", body: { userId } })).status).toBe(200);
    } finally { globalThis.fetch = originalFetch; }
    expect((await db.prepare('SELECT revoked FROM "oauthAccessToken" WHERE id = ?').bind("all-sessions").first<{ revoked: number | null }>())?.revoked).not.toBeNull();
  });
});
