import { expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { checkOidcAccess } from "../../src/access/oidc-gate";
import { ensureApplicationTables } from "../../src/db/schema";
import { createTestD1 } from "../test-d1";

test("an OIDC client with no application behind it is refused, whatever the provider has on file", async () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_BASE_URL: "https://auth.test" } as unknown as Env;
  await ensureApplicationTables(env);
  await db.prepare('CREATE TABLE "user" (id TEXT PRIMARY KEY, role TEXT, banned INTEGER)').run();
  await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, enabled, created_by, created_at, updated_at) VALUES ('a1', 'wiki', 'Wiki', 'oidc', 'registered-client', 1, 't', '2026-01-01', '2026-01-01')").run();
  const session = { user: { id: "u1", role: "user" }, session: { token: "t" } };

  const refused = await checkOidcAccess(env, "orphan-client", session);
  expect(refused?.status).toBe(403);
  expect(await refused?.json()).toEqual({ error: "access_denied", reason: "application_not_registered" });

  // A client bound to an application passes this gate (no policy row means no further limit).
  expect(await checkOidcAccess(env, "registered-client", session)).toBeNull();
});
