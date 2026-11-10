/**
 * Password policy family tests (docs/design/authentik-policies.md):
 * complexity, HIBP (stubbed), the strength estimator, history-based reuse
 * prevention, expiry with deny-only marking, and end-to-end enforcement
 * through password_entry / login bindings.
 *
 * `bun test tests/policies/password.test.ts`
 */

import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../../src/db/schema";
import { createTestD1 } from "../test-d1";
type TestD1Db = ReturnType<typeof createTestD1>["db"];
import {
  enforcePasswordEntry,
  evaluateLoginSurface,
  PASSWORD_ENTRY_REF,
  LOGIN_SURFACE_REF,
} from "../../src/policies/password-entry";
import {
  estimateStrength,
  getPasswordMeta,
  markPasswordUnusable,
  passwordHistoryAppend,
  passwordHistoryContains,
  recordPasswordChange,
  validatePasswordComplexity,
  validatePasswordConfig,
} from "../../src/policies/password";

async function envStub(): Promise<{ env: never; db: TestD1Db }> {
  const db = createTestD1().db;
  await ensureApplicationTables({ DB: db } as never);
  return { env: { DB: db } as never, db };
}

async function seedUser(db: TestD1, id: string): Promise<void> {
  // A minimal better-auth-shaped row is enough — snapshots degrade gracefully.
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY, email TEXT, name TEXT, username TEXT, role TEXT, banned TEXT)`,
  ).run();
  await db.prepare(
    `INSERT OR IGNORE INTO "user" (id, email, name, username, role) VALUES (?, ?, ?, ?, 'user')`,
  ).bind(id, `${id}@example.test`, id, id).run();
}

async function seedPolicy(
  db: TestD1,
  name: string,
  type: string,
  config: unknown,
  target: string,
  targetRef: string,
) {
  const policyId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO policies (id, name, type, config, enabled, execution_logging, created_by, created_at)
     VALUES (?, ?, ?, ?, 1, 0, 'admin', ?)`,
  ).bind(policyId, name, type, JSON.stringify(config), new Date().toISOString()).run();
  const bindingId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO policy_bindings
       (id, target, target_ref, policy_id, bind_user_id, bind_group_id, order_index, mode, negate,
        failure_result, enabled, created_by, created_at)
     VALUES (?, ?, ?, ?, NULL, NULL, 0, 'all', 0, 'fail', 1, 'admin', ?)`,
  ).bind(bindingId, target, targetRef, policyId, new Date().toISOString()).run();
  return bindingId;
}

describe("password complexity", () => {
  test("class minimums and symbol set produce user-visible messages", async () => {
    const config = validatePasswordConfig({ minLength: 12, minUpper: 1, minLower: 1, minDigit: 2, minSymbol: 1, checkHibp: false });
    const weak = await validatePasswordComplexity("Abc", config);
    expect(weak.passing).toBe(false);
    expect(weak.messages.length).toBeGreaterThanOrEqual(2);
    const strong = await validatePasswordComplexity("Correct-Horse-42!", { ...config, minSymbol: 1, minLength: 12 });
    expect(strong.passing).toBe(true);
  });

  test("the strength estimator penalizes repeated, sequential and keyboard patterns", () => {
    expect(estimateStrength("password")).toBe(0);
    expect(estimateStrength("aaaaaaa1")).toBeLessThanOrEqual(2);
    expect(estimateStrength("abcd1234")).toBeLessThanOrEqual(2);
    expect(estimateStrength("qweasd")).toBeLessThanOrEqual(2);
    expect(estimateStrength("7hZ!9kQ#2pLm")).toBeGreaterThanOrEqual(3);
    expect(estimateStrength("correct horse battery staple")).toBeGreaterThanOrEqual(3);
  });

  test("config bounds reject invalid values", () => {
    expect(() => validatePasswordConfig({ minLength: 4 })).toThrow("minLength");
    expect(() => validatePasswordConfig({ minScore: 9 })).toThrow("minScore");
  });
});

describe("password history and metadata", () => {
  test("history detects previously used candidates within the cap", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-hist");
    await passwordHistoryAppend(env as never, "u-hist", "old-pass-1");
    await passwordHistoryAppend(env as never, "u-hist", "old-pass-2");
    expect(await passwordHistoryContains(env as never, "u-hist", "old-pass-2", 5)).toBe(true);
    expect(await passwordHistoryContains(env as never, "u-hist", "fresh-pass", 5)).toBe(false);
    expect(await passwordHistoryContains(env as never, "someone-else", "old-pass-2", 5)).toBe(false);
  });

  test("recordPasswordChange clears the unusable flag; markPasswordUnusable sets it", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-meta");
    await markPasswordUnusable(env as never, "u-meta");
    expect((await getPasswordMeta(env as never, "u-meta"))?.unusable).toBe(true);
    await recordPasswordChange(env as never, "u-meta");
    const meta = await getPasswordMeta(env as never, "u-meta");
    expect(meta?.unusable).toBe(false);
    expect(meta?.changedAt).not.toBeNull();
  });
});

describe("password_entry surface enforcement", () => {
  test("complexity and reuse policies block weak or reused candidates", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-entry");
    await seedPolicy(db, "pw-complexity", "password", {
      minLength: 14, minUpper: 1, minLower: 1, minDigit: 2, minSymbol: 1, symbolSet: "!@#$",
      checkHibp: false, checkStrength: true, minScore: 2,
    }, "password_entry", PASSWORD_ENTRY_REF);
    await passwordHistoryAppend(env as never, "u-entry", "past-password-1");

    const weak = await enforcePasswordEntry(env as never, "u-entry", "short", { requestPath: "/test" });
    expect(weak.passing).toBe(false);
    expect(weak.messages.length).toBeGreaterThan(0);

    // A uniqueness policy rejects candidates that match stored digests.
    await seedPolicy(db, "pw-uniqueness", "password_uniqueness", { count: 5 }, "password_entry", PASSWORD_ENTRY_REF);
    await passwordHistoryAppend(env as never, "u-entry", "past-password-1");
    const reused = await enforcePasswordEntry(env as never, "u-entry", "past-password-1", { requestPath: "/test" });
    expect(reused.passing).toBe(false);
    expect(reused.messages.join()).toContain("used before");
    // A fresh candidate passes both bound policies.
    const fresh = await enforcePasswordEntry(env as never, "u-entry", "Uncommon-Phrase-77#", { requestPath: "/test" });
    expect(fresh.passing).toBe(true);
  });

  test("no bindings means password writes pass", async () => {
    const { env } = await envStub();
    const outcome = await enforcePasswordEntry(env as never, null, "anything", {});
    expect(outcome.passing).toBe(true);
    expect(outcome.bindings).toBe(0);
  });
});

describe("login surface with expiry policy", () => {
  test("a non-expired password passes; expiry policy can mark unusable", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-expiry");
    await recordPasswordChange(env as never, "u-expiry");
    const config = { days: 180, denyOnly: false };
    await seedPolicy(db, "pw-expiry", "password_expiry", config, "login", LOGIN_SURFACE_REF);
    const fresh = await evaluateLoginSurface(env as never, "u-expiry", { requestPath: "/sign-in/email" });
    expect(fresh.passing).toBe(true);

    // Age the changed_at row beyond the policy window.
    await db.prepare("UPDATE password_meta SET changed_at = ? WHERE user_id = ?")
      .bind(new Date(Date.now() - 200 * 86_400_000).toISOString(), "u-expiry").run();
    const expired = await evaluateLoginSurface(env as never, "u-expiry", { requestPath: "/sign-in/email" });
    expect(expired.passing).toBe(false);
    expect(expired.messages.join()).toContain("expired");
    // deny_only=false marks the password unusable.
    expect((await getPasswordMeta(env as never, "u-expiry"))?.unusable).toBe(true);
    // The next login is refused outright by the unusable flag.
    const nowUnusable = await evaluateLoginSurface(env as never, "u-expiry", {});
    expect(nowUnusable.passing).toBe(false);
    expect(nowUnusable.messages.join()).toContain("unusable");
  });
});

