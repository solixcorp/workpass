import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { ensureApplicationTables } from "../../src/db/schema";
import { mayEnrollFactor, recordSessionMfaProof } from "../../src/mfa/second-factor";
import { openStepUpChallenge } from "../../src/security/step-up";
import { TestD1 } from "../helpers/test-d1";

describe("factor enrollment guard", () => {
  test("bootstrap is allowed; existing factors and pending challenges need session proof", async () => {
    const db = new TestD1();
    const env = { DB: db, AUTH_BASE_URL: "https://idp.test", AUTH_SECRET: "test-secret" } as unknown as Env;
    await ensureApplicationTables(env);
    db.exec('CREATE TABLE "user" (id TEXT PRIMARY KEY, "twoFactorEnabled" INTEGER); CREATE TABLE "passkey" (id TEXT, "userId" TEXT); INSERT INTO "user" VALUES (\'u\', 0)');
    const session = { user: { id: "u" }, session: { token: "a" } };
    expect(await mayEnrollFactor(env, session)).toBe(true);
    await db.prepare("INSERT INTO mfa_hotp_tokens (id, user_id, label, secret_base32, counter, verified, created_at) VALUES ('h','u','key','secret',0,1,'2026')").run();
    expect(await mayEnrollFactor(env, session)).toBe(false);
    expect(await recordSessionMfaProof(env, "other", "u", "hotp")).toBe(true);
    expect(await mayEnrollFactor(env, session)).toBe(false);
    expect(await recordSessionMfaProof(env, "a", "u", "hotp")).toBe(true);
    expect(await mayEnrollFactor(env, session)).toBe(true);
    const b = { user: { id: "u" }, session: { token: "b" } };
    await openStepUpChallenge({ env, userId: "u", sessionToken: "b", reasons: [], requestPath: "/" });
    expect(await mayEnrollFactor(env, b)).toBe(false);
  });
});
