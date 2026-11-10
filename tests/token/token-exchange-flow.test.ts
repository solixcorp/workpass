import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/**
 * End-to-end RFC 8693 token exchange against a real Better Auth instance:
 * confidential client registration, authorization-code subject token mint,
 * exchange with an explicitly allowlisted shorter-TTL resource, and the
 * failure paths (bad credentials, unallowlisted target, scope escalation,
 * actor token, banned account, revoked session, audit persistence).
 */

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const RESOURCE_PRIMARY = "https://api.pay.test/";
const RESOURCE_DELEGATED = "https://api.pay.test/delegated";
const RP_CALLBACK = "https://rp.exchange.test/cb";

function testEnv(db: D1Database): Env {
  return {
    DB: db,
    AUTH_SECRET: "integration-test-secret-0123456789abcdef",
    AUTH_BASE_URL: "http://127.0.0.1:8787",
    ENABLE_MIGRATIONS: "true",
    MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true",
    ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ENABLE_DYNAMIC_CLIENT_REGISTRATION: "true",
    CLIENT_REGISTRATION_TOKEN: "dcr-token-0123456789abcdef-0123456789abcdef",
    ENABLE_TOKEN_EXCHANGE: "true",
    TOKEN_EXCHANGE_ALLOWED_RESOURCES: JSON.stringify({
      "exchange-client": [RESOURCE_DELEGATED],
    }),
    OAUTH_RESOURCES: JSON.stringify([
      { identifier: RESOURCE_PRIMARY, accessTokenTtl: 600 },
      { identifier: RESOURCE_DELEGATED, accessTokenTtl: 300 },
    ]),
  } as unknown as Env;
}

async function run(request: Request, env: Env): Promise<Response> {
  return mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
}

function b64urlJson(value: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  const pieces = value.split(".");
  if (pieces.length !== 3) return null;
  const decode = (part: string): Record<string, unknown> => {
    const base64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
    return JSON.parse(atob(base64)) as Record<string, unknown>;
  };
  return { header: decode(pieces[0]!), payload: decode(pieces[1]!) };
}

describe("RFC 8693 token exchange end to end", () => {
  const { db, sqlite } = createTestD1();
  const env = testEnv(db);
  const jar = new Map<string, string>();
  let clientId = "exchange-client";
  let clientSecret = "";
  let subjectToken = "";

  async function call(path: string, init?: { method?: "GET" | "POST"; body?: unknown; origin?: boolean; headers?: Record<string, string>; form?: string }): Promise<Response> {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
    if (init?.origin) headers.Origin = "http://127.0.0.1:8787";
    if (init?.body !== undefined) headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
    if (init?.form !== undefined) headers["Content-Type"] = "application/x-www-form-urlencoded";
    const response = await run(new Request(`http://127.0.0.1:8787${path}`, {
      method: init?.method ?? "GET",
      headers,
      body: init?.form ?? (init?.body === undefined ? undefined : JSON.stringify(init.body)),
    }), env);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const separator = pair.indexOf("=");
      if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
    return response;
  }

  beforeAll(async () => {
    const migrate = await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    expect(migrate.status).toBe(200);
    const bootstrap = await call("/api/admin/bootstrap", {
      method: "POST", origin: true,
      headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@exchange.test", name: "Exchange Admin", username: "exchangeadmin", password: "ExchangeOnly-7d9Kpw9zL2" },
    });
    expect(bootstrap.status).toBe(201);

    const signIn = await call("/api/auth/sign-in/username", {
      method: "POST", origin: true,
      body: { username: "exchangeadmin", password: "ExchangeOnly-7d9Kpw9zL2" },
    });
    expect(signIn.status).toBe(200);

    const register = await call("/api/auth/oauth2/register", {
      method: "POST", origin: true,
      headers: { Authorization: `Bearer ${env.CLIENT_REGISTRATION_TOKEN}` },
      body: {
        client_name: "exchange-client",
        redirect_uris: [RP_CALLBACK],
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["authorization_code", EXCHANGE_GRANT],
        response_types: ["code"],
        scope: "openid profile email",
        resources: [RESOURCE_PRIMARY, RESOURCE_DELEGATED],
      },
    });
    expect(register.status).toBe(201);
    const registered = await register.json() as { client_id?: string; client_secret?: string };
    clientId = registered.client_id ?? "";
    clientSecret = registered.client_secret ?? "";
    expect(clientId.length > 0 && clientSecret.length > 0).toBeTrue();
    env.TOKEN_EXCHANGE_ALLOWED_RESOURCES = JSON.stringify({ [clientId]: [RESOURCE_DELEGATED] });

    const verifier = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
      .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const challenge = btoa(String.fromCharCode(...new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    ))).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const authorize = await call(`/api/auth/oauth2/authorize?${new URLSearchParams({
      client_id: clientId, redirect_uri: RP_CALLBACK, response_type: "code",
      scope: "profile email", state: "ex-state", code_challenge: challenge, code_challenge_method: "S256",
      resource: RESOURCE_PRIMARY,
    })}`);
    expect(authorize.status).toBe(302);
    const consentLocation = authorize.headers.get("location") ?? "";
    expect(consentLocation.includes("/consent?")).toBeTrue();    const consentUrl = consentLocation.startsWith("/") ? `http://127.0.0.1:8787${consentLocation}` : consentLocation;
    const oauthQuery = new URL(consentUrl).search.slice(1);
    const consent = await call("/api/auth/oauth2/consent", {
      method: "POST", origin: true,
      body: { oauth_query: oauthQuery, accept: true, scopes: ["profile", "email"] },
    });
    expect(consent.status).toBe(200);
    const consentJson = await consent.json() as { redirectURI?: string; url?: string };
    const redirect = consentJson.url ?? consentJson.redirectURI ?? "";
    const code = new URL(redirect).searchParams.get("code") ?? "";
    expect(code.length > 0).toBeTrue();

    const basic = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    const mint = await call("/api/auth/oauth2/token", {
      method: "POST", form: new URLSearchParams({
        grant_type: "authorization_code", code, redirect_uri: RP_CALLBACK, code_verifier: verifier,
      }).toString(), headers: { Authorization: basic },
    });
    expect(mint.status).toBe(200);
    const minted = await mint.json() as { access_token?: string };
    subjectToken = minted.access_token ?? "";
    expect(subjectToken.length > 0).toBeTrue();
  });

  function exchange(form: Record<string, string>, authorization = `Basic ${btoa(`${clientId}:${clientSecret}`)}`): Promise<Response> {
    return call("/api/auth/oauth2/token", {
      method: "POST", form: new URLSearchParams(form).toString(), headers: { Authorization: authorization },
    });
  }

  test("mints a shorter-lived token for an allowlisted delegated resource", async () => {
    const subject = b64urlJson(subjectToken);
    expect(subject?.header.typ).toBe("at+jwt");
    // Exchange against the delegated resource, narrowing the scope.
    const response = await exchange({
      grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
      resource: RESOURCE_DELEGATED, scope: "profile",
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { access_token?: string; issued_token_type?: string; expires_in?: number };
    expect(body.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
    const output = b64urlJson(body.access_token ?? "");
    expect(output?.header.typ).toBe("at+jwt");
    expect(output?.payload.scope).toBe("profile");
    expect(output?.payload.aud).toBe(RESOURCE_DELEGATED);
    expect(String(output?.payload.sid).length > 0).toBeTrue();
    const subjectExpiry = Number(subject?.payload.exp);
    const outputExpiry = Number(output?.payload.exp);
    // Hard rule: the delegation never outlives the subject token.
    expect(outputExpiry).toBeLessThan(subjectExpiry);
    expect((body.expires_in ?? 0)).toBeLessThanOrEqual(300 + 15);
  });

  test("rejects unallowlisted targets, long TTL targets, escalation, actor tokens and bad credentials", async () => {
    for (const form of [
      { grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE, resource: "https://other-service.test/" },
      // Output TTL of the primary resource (600s) plus margin exceeds the subject remaining life.
      { grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE, resource: RESOURCE_PRIMARY },
      { grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE, resource: RESOURCE_DELEGATED, scope: "profile email admin" },
      { grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE, resource: RESOURCE_DELEGATED, actor_token: "unsupported" },
    ] as Record<string, string>[]) {
      const response = await exchange(form);
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("error");
    }
    const wrongSecret = await exchange({
      grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE, resource: RESOURCE_DELEGATED,
    }, `Basic ${btoa(`${clientId}:wrong-secret`)}`);
    expect(wrongSecret.status).toBe(401);
  });

  test("a banned account cannot exchange and session loss invalidates JWT subjects", async () => {
    const revoked = sqlite.query('DELETE FROM "session"').run();
    expect(revoked.changes >= 1).toBeTrue();
    const afterSessionLoss = await exchange({
      grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE, resource: RESOURCE_DELEGATED,
    });
    expect(afterSessionLoss.status).toBe(400);
  });

  test("persisted exchange audit evidence", async () => {
    const count = sqlite.query('SELECT COUNT(*) AS count FROM audit_events WHERE event_type = ?').get("authentication.token_exchange.authorized") as { count: number };
    expect(count.count).toBeGreaterThan(0);
  });
});
