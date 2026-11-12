import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { ensureApplicationTables } from "../../src/db/schema";
import { ENROLL_GATE_TTL_MS, enrollGateState, mayEnrollFactor, recordSessionMfaProof } from "../../src/mfa/second-factor";
import { openStepUpChallenge } from "../../src/security/step-up";
import { TestD1 } from "../helpers/test-d1";

describe("factor enrollment guard", () => {
  async function fixture() {
    const db = new TestD1();
    const env = { DB: db, AUTH_BASE_URL: "https://idp.test", AUTH_SECRET: "test-secret" } as unknown as Env;
    await ensureApplicationTables(env);
    db.exec('CREATE TABLE "user" (id TEXT PRIMARY KEY, "twoFactorEnabled" INTEGER); CREATE TABLE "passkey" (id TEXT, "userId" TEXT); INSERT INTO "user" VALUES (\'u\', 0)');
    return { db, env };
  }
  const gate = (db: TestD1, token: string, fields: { password?: number; second?: number }) =>
    db.prepare(
      `INSERT INTO mfa_enroll_gates (session_token, user_id, password_at, second_at) VALUES (?, 'u', ?, ?)
       ON CONFLICT (session_token) DO UPDATE SET password_at = excluded.password_at, second_at = excluded.second_at`,
    ).bind(token, fields.password ?? null, fields.second ?? null).run();

  test("an account with no factor still needs a fresh password and an emailed code", async () => {
    const { db, env } = await fixture();
    const session = { user: { id: "u" }, session: { token: "a" } };
    expect(await mayEnrollFactor(env, session)).toBe(false);
    expect(await enrollGateState(env, session)).toEqual({ passwordOk: false, secondOk: false, secondMode: "email" });
    await gate(db, "a", { password: Date.now() });
    expect(await mayEnrollFactor(env, session)).toBe(false);
    await gate(db, "a", { second: Date.now() });
    expect(await mayEnrollFactor(env, session)).toBe(false);
    await gate(db, "a", { password: Date.now(), second: Date.now() });
    expect(await mayEnrollFactor(env, session)).toBe(true);
  });

  test("reverification expires and never carries over to another session", async () => {
    const { db, env } = await fixture();
    const stale = Date.now() - ENROLL_GATE_TTL_MS - 1000;
    await gate(db, "a", { password: stale, second: stale });
    expect(await mayEnrollFactor(env, { user: { id: "u" }, session: { token: "a" } })).toBe(false);
    await gate(db, "a", { password: Date.now(), second: Date.now() });
    expect(await mayEnrollFactor(env, { user: { id: "u" }, session: { token: "b" } })).toBe(false);
    await db.prepare("UPDATE mfa_enroll_gates SET user_id = 'someone-else' WHERE session_token = 'a'").run();
    expect(await mayEnrollFactor(env, { user: { id: "u" }, session: { token: "a" } })).toBe(false);
  });

  test("an account with a factor needs that factor's session proof plus the password; a pending challenge blocks", async () => {
    const { db, env } = await fixture();
    const session = { user: { id: "u" }, session: { token: "a" } };
    await db.prepare("INSERT INTO mfa_hotp_tokens (id, user_id, label, secret_base32, counter, verified, created_at) VALUES ('h','u','key','secret',0,1,'2026')").run();
    expect((await enrollGateState(env, session)).secondMode).toBe("existing");
    await gate(db, "a", { password: Date.now(), second: Date.now() });
    expect(await mayEnrollFactor(env, session)).toBe(false); // the email-code timestamp is not a factor proof
    expect(await recordSessionMfaProof(env, "other", "u", "hotp")).toBe(true);
    expect(await mayEnrollFactor(env, session)).toBe(false);
    expect(await recordSessionMfaProof(env, "a", "u", "hotp")).toBe(true);
    expect(await mayEnrollFactor(env, session)).toBe(true);
    const b = { user: { id: "u" }, session: { token: "b" } };
    await gate(db, "b", { password: Date.now() });
    await recordSessionMfaProof(env, "b", "u", "hotp");
    expect(await mayEnrollFactor(env, b)).toBe(true);
    await openStepUpChallenge({ env, userId: "u", sessionToken: "b", reasons: [], requestPath: "/" });
    expect(await mayEnrollFactor(env, b)).toBe(false);
  });
});
