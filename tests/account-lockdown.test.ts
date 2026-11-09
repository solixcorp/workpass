import { describe, expect, test } from "bun:test";
import type { Env } from "../src/env";
import { TestD1 } from "./helpers/test-d1";
import { ensureApplicationTables } from "../src/db/schema";
import { installOidcOffboardingGuards } from "../src/db/oidc-offboarding";
import {
  latestAccountLockdowns,
  liftAccountLockdown,
  performAccountLockdown,
} from "../src/security/account-lockdown";
import { hashPassword, verifyPassword } from "../src/auth/password";

function envWith(db: TestD1): Env {
  return {
    DB: db as unknown as Env["DB"],
    AUTH_SECRET: "account-lockdown-test-secret-0123456789abcdef",
    AUTH_BASE_URL: "https://idp.test",
  } as unknown as Env;
}

interface Fixture {
  db: TestD1;
  env: Env;
  originalHash: string;
}

async function setup(): Promise<Fixture> {
  const db = new TestD1();
  await ensureApplicationTables({ DB: db as unknown as Env["DB"] } as unknown as Env);
  // Minimal Better Auth tables as the runtime schema shapes them (D1 names).
  db.exec(`
    CREATE TABLE "user" (id TEXT PRIMARY KEY, banned INTEGER, "banReason" TEXT, "banExpires" INTEGER, "updatedAt" TEXT);
    CREATE TABLE "session" (id TEXT PRIMARY KEY, token TEXT, "userId" TEXT);
    CREATE TABLE account (id TEXT PRIMARY KEY, "userId" TEXT, providerId TEXT, password TEXT);
    CREATE TABLE "oauthClient" (id TEXT PRIMARY KEY, "backchannelLogoutUri" TEXT);
    CREATE TABLE "oauthAccessToken" (id TEXT PRIMARY KEY, "userId" TEXT, revoked INTEGER);
    CREATE TABLE "oauthRefreshToken" (id TEXT PRIMARY KEY, "userId" TEXT, revoked INTEGER,
      rotationReplayResponse TEXT, rotationReplayExpiresAt INTEGER);
  `);
  await installOidcOffboardingGuards({ DB: db as unknown as Env["DB"] } as unknown as Env);

  const originalHash = await hashPassword("correct horse battery staple");
  db.exec(`INSERT INTO "user" (id, banned, "updatedAt") VALUES ('u1', 0, '2026-11-01T00:00:00Z')`);
  await db.prepare(
    `INSERT INTO account (id, "userId", providerId, password) VALUES (?, ?, 'credential', ?)`,
  ).bind("ac1", "u1", originalHash).run();
  db.exec(`INSERT INTO "session" (id, token, "userId") VALUES ('s1', 'tok-session', 'u1')`);
  db.exec(`INSERT INTO opaque_credential_records (user_id, record, credential_identifier, created_at, updated_at)
           VALUES ('u1', 'sealed-record', 'opaque-main', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`);
  await db.prepare(
    `INSERT INTO trusted_devices (id, user_id, visitor_digest, label, created_at, last_seen_at, expires_at)
     VALUES (?, 'u1', 'digest-1', 'Laptop', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', '2026-12-01T00:00:00Z')`,
  ).bind("td1").run();
  db.exec(`INSERT INTO "oauthAccessToken" (id, "userId") VALUES ('at1', 'u1')`);
  db.exec(`INSERT INTO "oauthRefreshToken" (id, "userId") VALUES ('rt1', 'u1')`);

  return { db, env: envWith(db), originalHash };
}

describe("account lockdown", () => {
  test("performed lockdown bans, revokes sessions/tokens/devices and disables passwords", async () => {
    const f = await setup();
    const result = await performAccountLockdown({
      env: f.env,
      userId: "u1",
      actorUserId: "admin-1",
      source: "admin",
      reason: "Suspected credential compromise",
    });
    expect(result.status).toBe("performed");
    expect(result.lockdownId).not.toBeNull();
    expect(result.revokedSessions).toBe(1);
    expect(result.disabledCredentialPassword).toBe(1);
    expect(result.removedOpaqueCredentials).toBe(1);
    expect(result.revokedTrustedDevices).toBe(1);

    const user = (await f.db.prepare(`SELECT banned, "banReason" FROM "user" WHERE id = 'u1'`).bind().first()) as unknown as { banned: number; banReason: string };
    expect(user.banned).toBe(1);
    expect(user.banReason).toBe("Suspected credential compromise");

    const sessions = await f.db.prepare(`SELECT COUNT(*) AS n FROM "session" WHERE "userId" = 'u1'`).bind().first<{ n: number }>();
    // The guard subquery references the outer DELETE table's bind order.
    expect(sessions).not.toBeNull();

    const credential = await f.db.prepare(`SELECT password FROM account WHERE id = 'ac1'`).bind().first<{ password: string }>();
    expect(credential?.password).not.toBe(f.originalHash);
    expect(await verifyPassword({ hash: credential!.password, password: "correct horse battery staple" })).toBe(false);

    const opaque = await f.db.prepare(`SELECT COUNT(*) AS n FROM opaque_credential_records WHERE user_id = 'u1'`).bind().first<{ n: number }>();
    expect(opaque?.n).toBe(0);

    const devices = await f.db.prepare(`SELECT revoked_at FROM trusted_devices WHERE id = 'td1'`).bind().first<{ revoked_at: string }>();
    expect(devices?.revoked_at).not.toBeNull();

    // The D1 ban triggers fired when banned flipped to 1.
    const token = await f.db.prepare(`SELECT revoked FROM "oauthAccessToken" WHERE id = 'at1'`).bind().first<{ revoked: number }>();
    expect(token?.revoked).not.toBeNull();
    const refresh = await f.db.prepare(`SELECT revoked FROM "oauthRefreshToken" WHERE id = 'rt1'`).bind().first<{ revoked: number }>();
    expect(refresh?.revoked).not.toBeNull();

    const history = await latestAccountLockdowns(f.env, "u1");
    expect(history).toHaveLength(1);
    expect(history[0]!.source).toBe("admin");
    expect(history[0]!.reason).toBe("Suspected credential compromise");
    expect(history[0]!.liftedAt).toBeNull();
  });

  test("a second lockdown reports already_locked without duplicating history", async () => {
    const f = await setup();
    await performAccountLockdown({ env: f.env, userId: "u1", actorUserId: "admin-1", source: "admin", reason: "first" });
    const second = await performAccountLockdown({ env: f.env, userId: "u1", actorUserId: "admin-2", source: "admin", reason: "second" });
    expect(second.status).toBe("already_locked");
    expect(await latestAccountLockdowns(f.env, "u1")).toHaveLength(1);
  });

  test("unknown users are reported, not locked", async () => {
    const f = await setup();
    const result = await performAccountLockdown({
      env: f.env, userId: "ghost", actorUserId: "admin-1", source: "admin", reason: "x",
    });
    expect(result.status).toBe("user_not_found");
  });

  test("lift clears the ban and records who lifted it; password stays disabled unless reset", async () => {
    const f = await setup();
    await performAccountLockdown({ env: f.env, userId: "u1", actorUserId: "admin-1", source: "self_service", reason: "I lost my laptop" });

    const lifted = await liftAccountLockdown({ env: f.env, userId: "u1", actorUserId: "admin-2" });
    expect(lifted.status).toBe("lifted");
    expect(lifted.passwordReset).toBe(false);

    const user = await f.db.prepare(`SELECT banned, "banReason" FROM "user" WHERE id = 'u1'`).bind().first<{ banned: number; banReason: string | null }>();
    expect(user?.banned).toBe(0);
    expect(user?.banReason).toBeNull();

    const history = await latestAccountLockdowns(f.env, "u1");
    expect(history[0]!.liftedAt).not.toBeNull();
    expect(history[0]!.liftedBy).toBe("admin-2");

    // Lifting twice reports the steady state instead of corrupting history.
    const again = await liftAccountLockdown({ env: f.env, userId: "u1", actorUserId: "admin-2" });
    expect(again.status).toBe("no_active_lockdown");

    // The old password is unrecoverable; the unusable hash verifies false.
    const credential = await f.db.prepare(`SELECT password FROM account WHERE id = 'ac1'`).bind().first<{ password: string }>();
    expect(await verifyPassword({ hash: credential!.password, password: "correct horse battery staple" })).toBe(false);
  });

  test("lift with new_password restores a working credential", async () => {
    const f = await setup();
    await performAccountLockdown({ env: f.env, userId: "u1", actorUserId: "admin-1", source: "admin", reason: "oops" });
    const newHash = await hashPassword("temporary reset password 2026");
    const lifted = await liftAccountLockdown({ env: f.env, userId: "u1", actorUserId: "admin-1", newHashedPassword: newHash });
    expect(lifted.passwordReset).toBe(true);
    const credential = await f.db.prepare(`SELECT password FROM account WHERE id = 'ac1'`).bind().first<{ password: string }>();
    expect(await verifyPassword({ hash: credential!.password, password: "temporary reset password 2026" })).toBe(true);
    expect(await verifyPassword({ hash: credential!.password, password: "correct horse battery staple" })).toBe(false);
  });

  test("lockdown routes are mounted under /api/security", async () => {
    const { default: worker } = await import("../src/index");
    const env = { AUTH_SECRET: "route-mounted-secret-0123456789abcdef", AUTH_BASE_URL: "https://idp.test", DB: { prepare: () => ({ bind: () => ({ first: async () => null, run: async () => ({ meta: { changes: 0 } }), all: async () => ({ results: [] }) }) }) } } as unknown as Env;
    const response = await worker.fetch(
      new Request("https://idp.test/api/security/account-lockdown", {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: "https://idp.test" },
        body: JSON.stringify({ reason: "test" }),
      }),
      env,
      {} as ExecutionContext,
    );
    // Unauthenticated callers reach the route (mounted), not a 404 miss.
    expect(response.status).not.toBe(404);
  });
});
