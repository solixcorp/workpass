import { expect, test } from "bun:test";
import { authRoutes } from "../../src/auth/routes";
import { migrationRoutes } from "../../src/admin/migrations";
import { webfingerRoutes } from "../../src/oidc/webfinger";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

test("WebFinger advertises the discovery issuer", async () => {
  const { db, sqlite } = createTestD1();
  try {
    const env = { DB: db, AUTH_BASE_URL: "https://idp.example.test", AUTH_SECRET: "test-secret-0123456789abcdef0123456789", OIDC_EMAIL_DOMAIN: "example.test", ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef012345" } as Env;
    const migration = await migrationRoutes.request("https://idp.example.test/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } }, env);
    expect(migration.status).toBe(200);
    const discovery = await authRoutes.request("https://idp.example.test/.well-known/openid-configuration", {}, env);
    const webfinger = await webfingerRoutes.request("https://example.test/webfinger?resource=acct%3Ajane%40example.test", {}, env);
    expect(discovery.status).toBe(200);
    expect(webfinger.status).toBe(200);
    const metadata = await discovery.json() as { issuer: string };
    const result = await webfinger.json() as { links: Array<{ href: string }> };
    expect(metadata.issuer).toBe("https://idp.example.test/api/auth");
    expect(result.links[0]?.href).toBe(metadata.issuer);
  } finally { sqlite.close(); }
});
