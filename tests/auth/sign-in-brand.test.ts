import { describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { signInBrandForClient } from "../../src/applications/sign-in-brand";
import { createTestD1 } from "../test-d1";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Brand-7d9Kpw9zL2xQ";

describe("sign-in card names the application that asked", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "brand-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();

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

  test("the brand follows the client, and a request must be signed to ask", async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    const now = new Date().toISOString();
    await db.prepare(
      `INSERT INTO applications (id, slug, name, description, protocol, binding, launch_url, icon_url, enabled, created_by, created_at, updated_at)
       VALUES ('a1', 'wiki', 'Company Wiki', '', 'oidc', 'client-wiki', NULL, 'https://wiki.example.com/icon.png', 1, 'system', ?, ?)`,
    ).bind(now, now).run();

    expect(await signInBrandForClient(env, "client-wiki")).toEqual({
      name: "Company Wiki", signInTitle: "Company Wiki에 로그인", icon: "https://wiki.example.com/icon.png",
    });
    expect(await signInBrandForClient(env, "nobody")).toBeNull();

    // A real signed request from the WorkPass flow names WorkPass; a tampered one reveals nothing.
    const login = await call("/auth/login?redirect=%2F");
    const authorize = new URL(login.headers.get("location")!);
    const signIn = new URL((await call(`${authorize.pathname}${authorize.search}`)).headers.get("location")!, ORIGIN);
    const handoff = await call(`${signIn.pathname}${signIn.search}`);
    const oq = new URL(handoff.headers.get("location")!, ORIGIN).searchParams.get("oq")!;
    const ok = await (await call("/api/config/login/app", { method: "POST", body: { oq } })).json() as { app: { name: string } | null };
    expect(ok.app?.name).toBe("WorkPass Dashboard");
    const forged = await (await call("/api/config/login/app", { method: "POST", body: { oq: `${oq}&client_id=client-wiki` } })).json() as { app: unknown };
    expect(forged.app).toBeNull();
    const bare = await (await call("/api/config/login/app", { method: "POST", body: { oq: "client_id=client-wiki" } })).json() as { app: unknown };
    expect(bare.app).toBeNull();
  });

  test("a browser that opens authorize without a device event is sent to the device check", async () => {
    await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@brand.test", name: "Admin", username: "brandadmin", password: PASSWORD },
    });
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "brandadmin", password: PASSWORD } })).status).toBe(200);
    (env as { FINGERPRINT_SERVER_API_KEY?: string; FINGERPRINT_BLOCK_SIGN_IN?: string }).FINGERPRINT_SERVER_API_KEY = "server-key-for-tests";
    (env as { FINGERPRINT_BLOCK_SIGN_IN?: string }).FINGERPRINT_BLOCK_SIGN_IN = "true";
    const path = "/api/auth/oauth2/authorize?client_id=client-wiki&response_type=code&state=s";

    const page = await call(path, { headers: { "Sec-Fetch-Mode": "navigate", Accept: "text/html" } });
    expect(page.status).toBe(302);
    const where = new URL(page.headers.get("location")!);
    expect(where.pathname).toBe("/verify-device");
    expect(where.searchParams.get("next")).toBe(path);

    // Programmatic callers keep the JSON answer.
    const api = await call(path, { headers: { Accept: "application/json" } });
    expect(api.status).toBe(403);
    expect(await api.json()).toEqual({ error: "Additional device verification is required" });
    // With blocking off the same request goes straight through to the provider.
    delete (env as { FINGERPRINT_BLOCK_SIGN_IN?: string }).FINGERPRINT_BLOCK_SIGN_IN;
    const open = await call(path, { headers: { "Sec-Fetch-Mode": "navigate", Accept: "text/html" } });
    expect(new URL(open.headers.get("location") ?? "http://x/", ORIGIN).pathname).not.toBe("/verify-device");
    delete (env as { FINGERPRINT_SERVER_API_KEY?: string }).FINGERPRINT_SERVER_API_KEY;
  });

  test("logging out through the provider ends on the web app's own screens", async () => {
    const nav = { "Sec-Fetch-Mode": "navigate", Accept: "text/html" };
    const ask = await mod.fetch(new Request(`${ORIGIN}/api/auth/oauth2/end-session`, { headers: nav, redirect: "manual" }), env,
      { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect(ask.status).toBe(303);
    expect(new URL(ask.headers.get("location")!).pathname).toBe("/logout");
    const cookie = ask.headers.getSetCookie().map((entry) => entry.split(";")[0]).join("; ");
    expect(cookie).toContain("oauth_logout_confirmation");

    const confirm = await mod.fetch(new Request(`${ORIGIN}/api/auth/oauth2/end-session/confirm`, {
      method: "POST", redirect: "manual", body: "action=confirm",
      headers: { ...nav, Origin: ORIGIN, Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded" },
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect(confirm.status).toBe(303);
    expect(new URL(confirm.headers.get("location")!).pathname).toBe("/logged-out");

    // A program calling the endpoint keeps the provider's own answer.
    const api = await call("/api/auth/oauth2/end-session", { headers: { Accept: "application/json" } });
    expect(api.status).not.toBe(303);
  });
});
