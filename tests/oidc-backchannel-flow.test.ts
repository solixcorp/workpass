import { expect, test } from "bun:test";
import worker from "../src/index";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";
import { generatePKCEPair, jwtVerify } from "./oidc-crypto";

test("OIDC sign-out sends a signed logout token to an approved RP", async () => {
  const { db, sqlite } = createTestD1();
  const base = "http://127.0.0.1:8787";
  const uri = "https://rp.example.test/logout";
  const env = { DB: db, AUTH_BASE_URL: base, AUTH_SECRET: "integration-secret-0123456789abcdef",
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-012345",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-012345",
    ENABLE_DYNAMIC_CLIENT_REGISTRATION: "true", CLIENT_REGISTRATION_TOKEN: "register-token-0123456789abcdef-012345" } as unknown as Env;
  const cookies = new Map<string, string>();
  const call = async (path: string, options: { method?: string; body?: unknown; headers?: Record<string, string>; form?: string } = {}) => {
    const headers: Record<string, string> = { Origin: base, ...options.headers };
    if (cookies.size) headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (options.form !== undefined) headers["Content-Type"] = "application/x-www-form-urlencoded";
    const res = await worker.fetch(new Request(base + path, { method: options.method ?? "GET", headers,
      body: options.form ?? (options.body === undefined ? undefined : JSON.stringify(options.body)) }), env, {} as ExecutionContext);
    for (const cookie of res.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const at = pair.indexOf("=");
      if (at > 0) cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return res;
  };
  expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
  sqlite.query("INSERT INTO oidc_logout_uri_approvals (uri) VALUES (?)").run(uri);
  expect((await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
    body: { username: "logoutadmin", email: "admin@logout.test", name: "Admin", password: "LogoutOnly-7d9Kpw9zL2" } })).status).toBe(201);
  expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "logoutadmin", password: "LogoutOnly-7d9Kpw9zL2" } })).status).toBe(200);
  const registration = await call("/api/auth/oauth2/register", { method: "POST", headers: { Authorization: `Bearer ${env.CLIENT_REGISTRATION_TOKEN}` }, body: {
    client_name: "logout-rp", redirect_uris: ["https://rp.example.test/callback"], backchannel_logout_uri: uri,
    backchannel_logout_session_required: true, token_endpoint_auth_method: "none", grant_types: ["authorization_code"],
    response_types: ["code"], scope: "openid profile email" } });
  expect(registration.status).toBe(201);
  const { client_id: clientId } = await registration.json() as { client_id: string };
  const pkce = await generatePKCEPair();
  const authorize = await call(`/api/auth/oauth2/authorize?${new URLSearchParams({ client_id: clientId,
    redirect_uri: "https://rp.example.test/callback", response_type: "code", scope: "openid profile email",
    code_challenge: pkce.challenge, code_challenge_method: "S256" })}`);
  expect(authorize.status).toBe(302);
  const oauthQuery = new URL(authorize.headers.get("location")!, base).search.slice(1);
  const consent = await call("/api/auth/oauth2/consent", { method: "POST", body: { oauth_query: oauthQuery, accept: true, scopes: ["openid", "profile", "email"] } });
  expect(consent.status).toBe(200);
  const redirect = await consent.json() as { url: string };
  const code = new URL(redirect.url).searchParams.get("code")!;
  const token = await call("/api/auth/oauth2/token", { method: "POST", form: new URLSearchParams({ client_id: clientId, grant_type: "authorization_code", code,
    redirect_uri: "https://rp.example.test/callback", code_verifier: pkce.verifier }).toString() });
  expect(token.status).toBe(200);
  const jwks = await (await call("/api/auth/jwks")).json() as { keys: Array<{ kty?: string; x?: string; y?: string; kid?: string }> };
  const originalFetch = globalThis.fetch;
  let logoutToken = "";
  try {
    globalThis.fetch = (async (input, init) => {
      expect(String(input)).toBe(uri);
      expect(init?.redirect).toBe("error");
      logoutToken = new URLSearchParams(String(init?.body)).get("logout_token") ?? "";
      return new Response(null, { status: 204 });
    }) as typeof fetch;
    expect((await call("/api/auth/sign-out", { method: "POST", body: {} })).status).toBe(200);
  } finally { globalThis.fetch = originalFetch; }
  expect(logoutToken).not.toBe("");
  const claims = await jwtVerify(logoutToken, jwks.keys) as (Record<string, unknown> | null);
  expect(claims?.iss).toBe(`${base}/api/auth`);
  expect(claims?.aud).toBe(clientId);
  expect(typeof claims?.sid).toBe("string");
  expect(claims?.events).toEqual({ "http://schemas.openid.net/event/backchannel-logout": {} });
  expect(claims?.nonce).toBeUndefined();
  expect(Number(claims?.exp)).toBeGreaterThan(Math.floor(Date.now() / 1000));
  sqlite.close();
});
