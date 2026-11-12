import { describe, expect, test } from "bun:test";
import { stripUntrustedOAuthQuery } from "../../src/auth/routes";
import mod from "../../src/index";
import { createTestD1 } from "../test-d1";
import type { Env } from "../../src/env";

describe("OAuth continuation request boundary", () => {
  for (const path of ["/api/auth/sign-in/email", "/api/auth/passkey/verify-authentication"]) {
    for (const type of ["application/json", "application/problem+json", "application/x-www-form-urlencoded", "multipart/form-data"]) {
      test(`${path} strips ${type}`, async () => {
        const form = new FormData();
        form.append("oauth_query", "signed");
        form.append("other", "keep");
        const body = type === "multipart/form-data" ? form : type.includes("json")
          ? JSON.stringify({ oauth_query: "signed", other: "keep" }) : "oauth_query=signed&other=keep";
        const headers = type === "multipart/form-data" ? undefined : { "content-type": type };
        const request = new Request(`https://example.test${path}?oauth_query=signed`, { method: "POST", headers, body });
        const result = await stripUntrustedOAuthQuery(request);
        expect(new URL(result.url).searchParams.has("oauth_query")).toBe(false);
        if (type.includes("json")) expect(await result.json()).toEqual({ other: "keep" });
        else {
          const parsed = await result.formData();
          expect(parsed.has("oauth_query")).toBe(false);
          expect(parsed.get("other")).toBe("keep");
        }
      });
    }
  }
  for (const path of ["authorize", "consent", "continue"]) {
    test(`${path} preserves the continuation`, async () => {
      const request = new Request(`https://example.test/api/auth/oauth2/${path}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ oauth_query: "signed" }),
      });
      expect(await (await stripUntrustedOAuthQuery(request)).json()).toEqual({ oauth_query: "signed" });
    });
  }
});

test("signed login handoff resumes only through the external policy gate", async () => {
  const origin = "http://127.0.0.1:8787";
  const password = "Activity-7d9Kpw9zL2";
  const { db, sqlite } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  async function call(path: string, body?: unknown, extra: Record<string, string> = {}) {
    const headers: Record<string, string> = { ...extra };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (body !== undefined) { headers.Origin = origin; headers["Content-Type"] = "application/json"; }
    const response = await mod.fetch(new Request(new URL(path, origin), {
      method: body === undefined ? "GET" : "POST", headers, redirect: "manual",
      body: body === undefined ? undefined : JSON.stringify(body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i > 0) { if (pair.slice(i + 1)) jar.set(pair.slice(0, i), pair.slice(i + 1)); else jar.delete(pair.slice(0, i)); }
    }
    return response;
  }
  expect((await call("/_internal/migrate", {}, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
  expect((await call("/api/admin/bootstrap", { email: "admin@handoff.test", name: "Admin", username: "handoff", password }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` })).status).toBe(201);
  expect((await call("/api/auth/sign-in/username", { username: "handoff", password })).status).toBe(200);
  const created = await (await call("/api/admin/oidc-clients", { name: "Wiki", applicationType: "web", redirectUris: ["https://wiki.example.com/callback"] })).json() as any;
  const clientId = created.client.clientId;
  sqlite.query('UPDATE "oauthClient" SET disabled = 0 WHERE clientId = ?').run(clientId);
  await call("/api/admin/applications", { slug: "wiki", name: "Wiki", protocol: "oidc", binding: clientId });
  const group = (await (await call("/api/admin/directory-groups", { name: "sales", description: "" })).json() as any).group;
  // Assignment endpoint uses PUT.
  const assignment = async (mode: string, groups?: string[]) => {
    const headers = { Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "), Origin: origin, "Content-Type": "application/json" };
    return mod.fetch(new Request(`${origin}/api/admin/applications/wiki/assignment`, { method: "PUT", headers, body: JSON.stringify({ mode, groups }) }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
  };
  expect((await assignment("groups", [group.id])).status).toBe(200);
  const adminJar = new Map(jar);
  jar.clear();
  const params = new URLSearchParams({ client_id: clientId, redirect_uri: "https://wiki.example.com/callback", response_type: "code", scope: "openid profile email", state: "s", code_challenge: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", code_challenge_method: "S256" });
  const authorize = await call(`/api/auth/oauth2/authorize?${params}`);
  expect(authorize.status).toBe(302);
  const signInUrl = authorize.headers.get("location")!;
  const signIn = await call(signInUrl);
  expect(signIn.status).toBe(302);
  const oq = new URL(signIn.headers.get("location")!, origin).searchParams.get("oq")!;
  expect(oq).toBeTruthy();
  expect((await call(`/sign-in?${oq}&client_id=forged`)).status).toBe(400);
  const login = await call("/api/auth/sign-in/username", { username: "handoff", password, oauth_query: oq });
  expect(login.status).toBe(200);
  const loginBody = JSON.stringify(await login.json());
  expect(loginBody).not.toContain("code=");
  expect(loginBody).not.toContain("consent");
  const denied = await call("/api/auth/oauth2/continue", { postLogin: true, oauth_query: oq });
  expect(denied.status).toBe(403);
  expect(await denied.json()).toMatchObject({ error: "access_denied" });
  jar.clear(); for (const [k, v] of adminJar) jar.set(k, v);
  expect((await assignment("everyone")).status).toBe(200);
  const allowed = await call("/api/auth/oauth2/continue", { postLogin: true, oauth_query: oq });
  expect(allowed.status).toBe(200);
  expect((await allowed.json() as any).url).toContain("consent");
});
