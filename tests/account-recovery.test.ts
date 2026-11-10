import { describe, expect, test } from "bun:test";
import type { Env } from "../src/env";
import { TestD1 } from "./helpers/test-d1";
import { ensureApplicationTables } from "../src/db/schema";
import {
  cleanupRecoveryTokens,
  issueRecoveryToken,
  redeemRecoveryToken,
} from "../src/security/account-recovery";
import { hashPassword, verifyPassword } from "../src/auth/password";

function envWith(db: TestD1, extra: Record<string, string> = {}): Env {
  return {
    DB: db as unknown as Env["DB"],
    AUTH_SECRET: "recovery-test-secret-0123456789abcdef",
    AUTH_BASE_URL: "https://idp.test",
    ...extra,
  } as unknown as Env;
}

interface Fixture {
  db: TestD1;
  env: Env;
}

async function setup(): Promise<Fixture> {
  const db = new TestD1();
  await ensureApplicationTables({ DB: db as unknown as Env["DB"] } as unknown as Env);
  db.exec(`
    CREATE TABLE "user" (id TEXT PRIMARY KEY, banned INTEGER, "banReason" TEXT, "banExpires" INTEGER, "updatedAt" TEXT);
    CREATE TABLE "session" (id TEXT PRIMARY KEY, token TEXT, "userId" TEXT);
    CREATE TABLE account (id TEXT PRIMARY KEY, "userId" TEXT, providerId TEXT, password TEXT);
  `);
  // Mirror the real lockdown state: the credential is an unusable random hash,
  // exactly what performAccountLockdown leaves behind.
  const unusable = await hashPassword(`unusable-${crypto.randomUUID()}`);
  db.exec(`INSERT INTO "user" (id, banned, "banReason") VALUES ('u1', 1, 'Locked down')`);
  await db.prepare(`INSERT INTO account (id, "userId", providerId, password) VALUES ('ac1', 'u1', 'credential', ?)`)
    .bind(unusable).run();
  db.exec(`INSERT INTO "session" (id, token, "userId") VALUES ('s1', 'tok-session', 'u1')`);
  await db.prepare(
    `INSERT INTO account_lockdowns (id, user_id, actor_user_id, source, reason, created_at, lifted_at, lifted_by)
     VALUES ('ld1', 'u1', 'admin-1', 'admin', 'Suspected compromise', '2026-11-10T00:00:00Z', NULL, NULL)`,
  ).bind().run();
  return { db, env: envWith(db) };
}

describe("recovery token issuance", () => {
  test("requires an active lockdown", async () => {
    const f = await setup();
    const none = await issueRecoveryToken({ env: f.env, userId: "ghost", actorUserId: "admin-1" });
    expect(none.status).toBe("user_not_found");

    await f.db.prepare(`UPDATE account_lockdowns SET lifted_at = '2026-11-10T01:00:00Z', lifted_by = 'admin-2' WHERE id = 'ld1'`).bind().run();
    const lifted = await issueRecoveryToken({ env: f.env, userId: "u1", actorUserId: "admin-1" });
    expect(lifted.status).toBe("no_active_lockdown");
  });

  test("issues a one-time token bound to the lockdown; TTL window is respected", async () => {
    const f = await setup();
    const issued = await issueRecoveryToken({ env: f.env, userId: "u1", actorUserId: "admin-1", ttlMinutes: 10 });
    expect(issued.status).toBe("issued");
    if (issued.status !== "issued") return;
    expect(issued.recovery.token.length).toBeGreaterThanOrEqual(40);
    expect(issued.lockdownId).toBe("ld1");
    const expiryGapMs = Date.parse(issued.expiresAt) - Date.now();
    expect(expiryGapMs).toBeGreaterThan(9 * 60_000);
    expect(expiryGapMs).toBeLessThanOrEqual(10 * 60_000);

    // The digest, not the token, is persisted.
    const raw = await f.db.prepare(`SELECT * FROM account_recovery_tokens WHERE user_id = 'u1'`).bind().first<Record<string, unknown>>();
    expect(JSON.stringify(raw)).not.toContain(issued.recovery.token);
  });
});

describe("recovery redemption", () => {
  test("resets the password, unbans, lifts the lockdown and consumes the token", async () => {
    const f = await setup();
    const issued = await issueRecoveryToken({ env: f.env, userId: "u1", actorUserId: "admin-1" });
    if (issued.status !== "issued") throw new Error("expected issuance");

    // The unusable post-lockdown credential must first fail verification —
    // even the owner's remembered password no longer works.
    const credentialBefore = await f.db.prepare(`SELECT password FROM account WHERE id = 'ac1'`).bind().first<{ password: string }>();
    expect(await verifyPassword({ hash: credentialBefore!.password, password: "pre-lockdown password!" })).toBe(false);

    const wrongToken = await redeemRecoveryToken({ env: f.env, token: `${issued.recovery.token}tampered`, newPassword: "Brand New Password 1" });
    expect(wrongToken.status).toBe("invalid_or_expired");

    const result = await redeemRecoveryToken({ env: f.env, token: issued.recovery.token, newPassword: "Brand New Password 1" });
    expect(result.status).toBe("recovered");
    expect(result.passwordReset).toBe(true);

    const user = await f.db.prepare(`SELECT banned FROM "user" WHERE id = 'u1'`).bind().first<{ banned: number }>();
    expect(user?.banned).toBe(0);
    const credential = await f.db.prepare(`SELECT password FROM account WHERE id = 'ac1'`).bind().first<{ password: string }>();
    expect(await verifyPassword({ hash: credential!.password, password: "Brand New Password 1" })).toBe(true);
    expect(await verifyPassword({ hash: credential!.password, password: "pre-lockdown password!" })).toBe(false);

    const lockdown = await f.db.prepare(`SELECT lifted_at, lifted_by FROM account_lockdowns WHERE id = 'ld1'`).bind().first<{ lifted_at: string; lifted_by: string }>();
    expect(lockdown?.lifted_at).not.toBeNull();
    expect(lockdown?.lifted_by).toBe("recovery_link");

    const sessions = await f.db.prepare(`SELECT COUNT(*) AS n FROM "session" WHERE "userId" = 'u1'`).bind().first<{ n: number }>();
    expect(sessions?.n).toBe(0);

    // Single use.
    const again = await redeemRecoveryToken({ env: f.env, token: issued.recovery.token, newPassword: "Another Password 22" });
    expect(again.status).toBe("invalid_or_expired");
    const credentialAfter = await f.db.prepare(`SELECT password FROM account WHERE id = 'ac1'`).bind().first<{ password: string }>();
    expect(await verifyPassword({ hash: credentialAfter!.password, password: "Brand New Password 1" })).toBe(true);
  });

  test("an already-lifted lockdown refuses redemption", async () => {
    const f = await setup();
    const issued = await issueRecoveryToken({ env: f.env, userId: "u1", actorUserId: "admin-1" });
    if (issued.status !== "issued") throw new Error("expected issuance");
    await f.db.prepare(`UPDATE account_lockdowns SET lifted_at = '2026-11-10T02:00:00Z', lifted_by = 'admin-2' WHERE id = 'ld1'`).bind().run();
    const result = await redeemRecoveryToken({ env: f.env, token: issued.recovery.token, newPassword: "Another Password 22" });
    expect(result.status).toBe("no_active_lockdown");
    // The token stays unconsumed for reconciliation.
    const row = await f.db.prepare(`SELECT used_at FROM account_recovery_tokens`).bind().first<{ used_at: string | null }>();
    expect(row?.used_at).toBeNull();
  });

  test("expired tokens are invalid; cleanup removes them", async () => {
    const f = await setup();
    const issued = await issueRecoveryToken({ env: f.env, userId: "u1", actorUserId: "admin-1", ttlMinutes: 5 });
    if (issued.status !== "issued") throw new Error("expected issuance");
    await f.db.prepare(`UPDATE account_recovery_tokens SET expires_at = ?`)
      .bind(new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString())
      .run();
    const result = await redeemRecoveryToken({ env: f.env, token: issued.recovery.token, newPassword: "Brand New Password 1" });
    expect(result.status).toBe("invalid_or_expired");
    await cleanupRecoveryTokens(f.env, new Date());
    const rows = await f.db.prepare(`SELECT COUNT(*) AS n FROM account_recovery_tokens`).bind().first<{ n: number }>();
    expect(rows?.n).toBe(0);
  });

  test("garbage tokens are rejected without touching state", async () => {
    const f = await setup();
    for (const token of ["", "short", "../../etc/passwd", "x".repeat(500)]) {
      const result = await redeemRecoveryToken({ env: f.env, token, newPassword: "Brand New Password 1" });
      expect(result.status).toBe("invalid_or_expired");
    }
    const rows = await f.db.prepare(`SELECT COUNT(*) AS n FROM account_recovery_tokens`).bind().first<{ n: number }>();
    expect(rows?.n).toBe(0);
  });
});
