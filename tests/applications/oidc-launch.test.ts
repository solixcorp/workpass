import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

const ORIGIN = "http://127.0.0.1:8787";

describe("OIDC application launch", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "launch-test-secret-0123456789abcdef-012345",
    AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string>; anonymous?: boolean }) {
    const headers: Record<string, string> = { ...init?.headers };
    if (!init?.anonymous && jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers,
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const i = pair.indexOf("=");
      if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return response;
  }

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    expect((await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@launch.test", name: "Admin", username: "launchadmin", password: "LaunchTest-7d9Kpw9zL2" },
    })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "launchadmin", password: "LaunchTest-7d9Kpw9zL2" } })).status).toBe(200);
    for (const [slug, protocol, url] of [
      ["oidc-app", "oidc", "https://app.example.test/login/initiate"],
      ["bookmark-app", "bookmark", "https://bookmark.example.test"],
      ["no-launch", "oidc", null],
      ["saml-app", "saml", "https://saml.example.test/login"],
      ["wsfed-app", "wsfed", "https://wsfed.example.test/login"],
      ["swa-app", "swa", "https://swa.example.test/login"],
    ]) {
      await db.prepare(`INSERT INTO applications (id, slug, name, protocol, launch_url, enabled, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, 'test', '2026-01-01', '2026-01-01')`).bind(slug, slug, slug, protocol, url).run();
    }
  });

  test("OIDC launch URL uses the discovery issuer without exposing a login hint", async () => {
    const discovery = await call("/.well-known/openid-configuration");
    expect(discovery.status).toBe(200);
    const { issuer } = await discovery.json() as { issuer: string };
    const response = await call("/api/applications");
    expect(response.status).toBe(200);
    const { applications } = await response.json() as { applications: Array<{ slug: string; launchUrl: string | null; launchInitiatesLogin: boolean }> };
    const app = applications.find((item) => item.slug === "oidc-app")!;
    expect(app.launchInitiatesLogin).toBe(true);
    const url = new URL(app.launchUrl!);
    expect(url.origin + url.pathname).toBe("https://app.example.test/login/initiate");
    expect([...url.searchParams.entries()]).toEqual([["iss", issuer]]);

    for (const [slug, launchUrl] of [
      ["bookmark-app", "https://bookmark.example.test"],
      ["saml-app", "https://saml.example.test/login"],
      ["wsfed-app", "https://wsfed.example.test/login"],
      ["swa-app", "https://swa.example.test/login"],
      ["no-launch", null],
      ["workpass-dashboard", (await db.prepare("SELECT launch_url FROM applications WHERE slug = 'workpass-dashboard'").first<{ launch_url: string }>())!.launch_url],
    ]) {
      expect(applications.find((item) => item.slug === slug)).toMatchObject({ launchUrl, launchInitiatesLogin: false });
    }
  });

  test("anonymous requests are rejected", async () => {
    expect((await call("/api/applications", { anonymous: true })).status).toBe(401);
  });
});
