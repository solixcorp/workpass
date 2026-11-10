import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { oauth1HmacSha1, oauthPercentEncode } from "../../src/oauth1/signature";

/**
 * End-to-end OAuth 1.0a (RFC 5849, HMAC-SHA1) against a real Better Auth
 * worker: consumer registration (operator token), temporary credentials,
 * browser authorization (sign-in + approve), access-token exchange with the
 * verifier, single-use enforcement and revocation.
 */

const HEADER = (values: Record<string, string>): string =>
  `OAuth ${Object.entries(values).map(([k, v]) => `${oauthPercentEncode(k)}="${oauthPercentEncode(v)}"`).join(", ")}`;

describe("OAuth 1.0a server end to end", () => {
  const { db, sqlite } = createTestD1();
  const env = {
    DB: db,
    AUTH_SECRET: "integration-test-secret-0123456789abcdef",
    AUTH_BASE_URL: "http://127.0.0.1:8787",
    ENABLE_MIGRATIONS: "true",
    MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true",
    ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ENABLE_OAUTH1: "true",
    OAUTH1_MANAGEMENT_TOKEN: "oauth1-mgmt-token-0123456789abcdef01234",
    AEAD_SEALING_KEY: btoa("oauth1-test-sealing-key-32-bytes"),
  } as unknown as Env;

  const jar = new Map<string, string>();
  let consumerKey = "";
  let consumerSecret = "";

  async function call(path: string, init?: { method?: string; body?: unknown; form?: string; headers?: Record<string, string>; redirect?: RequestRedirect }): Promise<Response> {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = Array.from(jar.entries()).map(([n, v]) => `${n}=${v}`).join("; ");
    if (init?.body !== undefined) headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
    if (init?.form !== undefined) headers["Content-Type"] = "application/x-www-form-urlencoded";
    const response = await mod.fetch(new Request(`http://127.0.0.1:8787${path}`, {
      method: init?.method ?? "GET", headers,
      body: init?.form ?? (init?.body === undefined ? undefined : JSON.stringify(init.body)),
      redirect: init?.redirect ?? "manual",
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const separator = pair.indexOf("=");
      if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
    return response;
  }

  /** Build a signed OAuth 1.0 request targeting the platform. */
  async function signedRequest(
    method: string, path: string, credentials: { key: string; secret: string; token?: string; tokenSecret?: string },
    extraParameters: Record<string, string>, body?: Record<string, string>,
  ): Promise<Request> {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomUUID().replace(/-/g, "");
    const parameters: Record<string, string> = {
      oauth_consumer_key: credentials.key, oauth_nonce: nonce,
      oauth_signature_method: "HMAC-SHA1", oauth_timestamp: timestamp,
      oauth_version: "1.0", ...extraParameters,
    };
    if (credentials.token) parameters.oauth_token = credentials.token;
    const url = `http://127.0.0.1:8787${path}`;
    const bodyPairs: [string, string][] = body ? Object.entries(body) : [];
    // The signature base string includes query parameters and form fields too.
    const formParams = bodyPairs.map(([k, v]) => `${oauthPercentEncode(k)}=${oauthPercentEncode(v)}`).join("&");
    const baseParameters: [string, string][] = [...Object.entries(parameters)];
    const base = await buildBaseString(method, url, baseParameters, bodyPairs);
    const signature = await oauth1HmacSha1(base, credentials.secret, credentials.tokenSecret ?? "");
    const header = HEADER({ ...parameters, oauth_signature: signature });
    const headers: Record<string, string> = { Authorization: header };
    if (body !== undefined) headers["Content-Type"] = "application/x-www-form-urlencoded";
    return new Request(url, { method, headers, body: body === undefined ? undefined : formParams });
  }

  async function buildBaseString(
    method: string, requestUrl: string, oauthParameters: [string, string][], bodyPairs: [string, string][],
  ): Promise<string> {
    const { oauth1SignatureBaseString } = await import("../../src/oauth1/signature");
    return oauth1SignatureBaseString(method, requestUrl, [...oauthParameters, ...bodyPairs]);
  }

  beforeAll(async () => {
    const migrate = await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    expect(migrate.status).toBe(200);
    const registered = await call("/api/oauth1/consumers", {
      method: "POST", headers: { Authorization: `Bearer ${env.OAUTH1_MANAGEMENT_TOKEN}` },
      body: { consumer_name: "legacy-app" },
    });
    expect(registered.status).toBe(201);
    const consumer = await registered.json() as { consumer_key: string; consumer_secret: string };
    consumerKey = consumer.consumer_key;
    consumerSecret = consumer.consumer_secret;
    // Signed-in operator user for the authorize step.
    const bootstrap = await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@oauth1.test", name: "OAuth1 Admin", username: "oauth1admin", password: "LegalOnly-7d9Kpw9zL2" },
    });
    expect(bootstrap.status).toBe(201);
    const sign = await call("/api/auth/sign-in/username", {
      method: "POST", body: { username: "oauth1admin", password: "LegalOnly-7d9Kpw9zL2" },
    });
    expect(sign.status).toBe(200);
  });

  test("full 3-legged flow issues and revokes an access token", async () => {
    // 1. Temporary credentials.
    const initiate = await call("/api/oauth1/initiate", {
      method: "POST", redirect: "manual",
    });
    // (request built below through signedRequest is required; direct call must fail)
    expect(initiate.status).toBe(401);

    const signedInitiate = await mod.fetch(await signedRequest("POST", "/api/oauth1/initiate", { key: consumerKey, secret: consumerSecret }, { oauth_callback: "oob" }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect(signedInitiate.status).toBe(200);
    const temp = Object.fromEntries(new URLSearchParams(await signedInitiate.text()));
    expect(temp.oauth_callback_confirmed).toBe("true");
    expect(temp.oauth_token?.startsWith("oat_")).toBeTrue();

    // 2. Browser authorization: approve with the signed-in session.
    const authorize = await call(`/api/oauth1/authorize?oauth_token=${temp.oauth_token}`);
    expect(authorize.status).toBe(200);
    const approve = await call("/api/oauth1/authorize/approve", {
      method: "POST", form: new URLSearchParams({ oauth_token: temp.oauth_token!, decision: "approve" }).toString(), redirect: "manual",
    });
    expect(approve.status).toBe(200);
    // The verifier is delivered on the out-of-band page.
    const approveHtml = await approve.text();
    const verifier = /<strong>(ovf_[^<]+)<\/strong>/.exec(approveHtml)?.[1] ?? "";
    expect(verifier.startsWith("ovf_")).toBeTrue();

    // 3. Access token exchange (verifier single use, in the OAuth header).
    const tokenRequest = await signedRequest("POST", "/api/oauth1/token", { key: consumerKey, secret: consumerSecret, token: temp.oauth_token, tokenSecret: temp.oauth_token_secret }, { oauth_verifier: verifier });
    const exchanged = await mod.fetch(tokenRequest, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect(exchanged.status).toBe(200);
    const access = Object.fromEntries(new URLSearchParams(await exchanged.text()));
    expect(access.oauth_token?.startsWith("oac_")).toBeTrue();

    // The temporary token is consumed: replaying the exchange fails.
    const replay = await mod.fetch(await signedRequest("POST", "/api/oauth1/token", { key: consumerKey, secret: consumerSecret, token: temp.oauth_token, tokenSecret: temp.oauth_token_secret }, { oauth_verifier: verifier }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect(replay.status).toBe(401);

    // Revoke and confirm.
    const revoke = await call("/api/oauth1/token/revoke", { method: "POST", headers: { Authorization: `Bearer ${access.oauth_token}` } });
    expect(revoke.status).toBe(200);
    const revokedAgain = await call("/api/oauth1/token/revoke", { method: "POST", headers: { Authorization: `Bearer ${access.oauth_token}` } });
    expect(revokedAgain.status).toBe(404);
  });

  test("unauthorized management endpoints fail closed", async () => {
    const anonymous = await call("/api/oauth1/consumers", { method: "POST", body: { consumer_name: "x" } });
    expect(anonymous.status).toBe(401);
    const disabledFeature = await mod.fetch(new Request("http://127.0.0.1:8787/api/oauth1/authorize", { method: "GET" }), {
      ...env, ENABLE_OAUTH1: "false",
    } as unknown as Env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect(disabledFeature.status).toBe(404);
  });

  test("audit records exist across the flow", async () => {
    const rows = sqlite.query("SELECT event_type FROM audit_events WHERE request_path LIKE '/api/oauth1%' GROUP BY event_type").all() as { event_type: string }[];
    const types = rows.map((row) => row.event_type);
    expect(types).toContain("oauth1.temporary.issue");
    expect(types).toContain("oauth1.authorize.approved");
    expect(types).toContain("oauth1.access.issue");
  });
});
