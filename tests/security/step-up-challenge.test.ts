import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { TestD1 } from "../helpers/test-d1";
import { ensureApplicationTables } from "../../src/db/schema";
import {
  cleanupStepUpChallenges,
  getStepUpChallenge,
  openStepUpChallenge,
  satisfyPendingStepUpChallenges,
  stepUpChallengeTtlSeconds,
  usableSecondFactors,
  validateStepUpConfig,
} from "../../src/security/step-up";
import { recordSessionMfaProof } from "../../src/mfa/second-factor";

function envWith(db: TestD1, extra: Record<string, string> = {}): Env {
  return {
    DB: db as unknown as Env["DB"],
    AUTH_SECRET: "step-up-test-secret-0123456789abcdef",
    AUTH_BASE_URL: "https://idp.test",
    ...extra,
  } as unknown as Env;
}

async function setup(): Promise<TestD1> {
  const db = new TestD1();
  await ensureApplicationTables({ DB: db as unknown as Env["DB"] } as unknown as Env);
  return db;
}

describe("step-up configuration", () => {
  test("TTL defaults to 900s and is bounds-checked", () => {
    expect(stepUpChallengeTtlSeconds({} as Env)).toBe(900);
    expect(stepUpChallengeTtlSeconds({ STEP_UP_CHALLENGE_TTL_SECONDS: "600" } as unknown as Env)).toBe(600);
    expect(() => stepUpChallengeTtlSeconds({ STEP_UP_CHALLENGE_TTL_SECONDS: "100" } as unknown as Env)).toThrow(
      "STEP_UP_CHALLENGE_TTL_SECONDS",
    );
    expect(() => validateStepUpConfig({ STEP_UP_CHALLENGE_TTL_SECONDS: "5000" } as unknown as Env)).toThrow();
  });
});

describe("challenge lifecycle", () => {
  test("open → pending → satisfied(when proof recorded) → allow", async () => {
    const db = await setup();
    const env = envWith(db);
    expect(await openStepUpChallenge({
      env, sessionToken: "tok-1", userId: "u1", reasons: ["impossible_travel"], requestPath: "/api/auth/sign-in/email",
    })).toBe(true);
    let status = await getStepUpChallenge(env, "tok-1");
    expect(status.state).toBe("pending");
    expect(status.reasons).toEqual(["impossible_travel"]);
    expect(status.expiresAt).not.toBeNull();

    // Recording a durable proof satisfies every open challenge of the user.
    const recorded = await recordSessionMfaProof(env, "tok-rotated", "u1");
    expect(recorded).toBe(true);
    status = await getStepUpChallenge(env, "tok-1");
    expect(status.state).toBe("satisfied");
    expect(status.satisfiedMethod).toBe("mfa_proof");

    // Sessions without a challenge report none — the gate lets them pass once
    // they carry a proof themselves.
    expect((await getStepUpChallenge(env, "tok-rotated")).state).toBe("none");
    expect((await getStepUpChallenge(env, "unknown-token")).state).toBe("none");
  });

  test("expiry turns a pending challenge into an expired state", async () => {
    const db = await setup();
    const env = envWith(db);
    await openStepUpChallenge({
      env, sessionToken: "tok-1", userId: "u1", reasons: ["history_distance_exceeded"], requestPath: "/api/auth/oauth2/authorize",
    });
    await db.prepare(`UPDATE session_step_up_requirements SET challenge_expires_at = ? WHERE session_token = 'tok-1'`)
      .bind(new Date(Date.now() - 1000).toISOString())
      .run();
    const status = await getStepUpChallenge(env, "tok-1");
    expect(status.state).toBe("expired");
  });

  test("satisfy is user-scoped and respects the window", async () => {
    const db = await setup();
    const env = envWith(db);
    await openStepUpChallenge({ env, sessionToken: "tok-a", userId: "u1", reasons: [], requestPath: "/p" });
    await openStepUpChallenge({ env, sessionToken: "tok-b", userId: "u1", reasons: [], requestPath: "/p" });
    await openStepUpChallenge({ env, sessionToken: "tok-c", userId: "u2", reasons: [], requestPath: "/p" });
    // Expire one of u1's challenges.
    await db.prepare(`UPDATE session_step_up_requirements SET challenge_expires_at = ? WHERE session_token = 'tok-b'`)
      .bind(new Date(Date.now() - 1000).toISOString())
      .run();
    const satisfied = await satisfyPendingStepUpChallenges(env, "u1");
    expect(satisfied).toBe(1);
    expect((await getStepUpChallenge(env, "tok-a")).state).toBe("satisfied");
    expect((await getStepUpChallenge(env, "tok-b")).state).toBe("expired");
    expect((await getStepUpChallenge(env, "tok-c")).state).toBe("pending");
  });

  test("reopening resets an old requirement for the same token", async () => {
    const db = await setup();
    const env = envWith(db);
    await openStepUpChallenge({ env, sessionToken: "tok-1", userId: "u1", reasons: ["a"], requestPath: "/p" });
    await db.prepare(`UPDATE session_step_up_requirements SET satisfied_at = ? WHERE session_token = 'tok-1'`)
      .bind(new Date().toISOString())
      .run();
    await openStepUpChallenge({ env, sessionToken: "tok-1", userId: "u1", reasons: ["b"], requestPath: "/p2" });
    const status = await getStepUpChallenge(env, "tok-1");
    expect(status.state).toBe("pending");
    expect(status.reasons).toEqual(["b"]);
    expect(status.requestPath).toBe("/p2");
  });

  test("cleanup removes expired open challenges and stale satisfied rows", async () => {
    const db = await setup();
    const env = envWith(db);
    await openStepUpChallenge({ env, sessionToken: "tok-old", userId: "u1", reasons: [], requestPath: "/p" });
    await openStepUpChallenge({ env, sessionToken: "tok-sat", userId: "u1", reasons: [], requestPath: "/p" });
    await db.prepare(`UPDATE session_step_up_requirements SET challenge_expires_at = ? WHERE session_token = 'tok-old'`)
      .bind(new Date(Date.now() - 2000).toISOString())
      .run();
    await db.prepare(`UPDATE session_step_up_requirements SET satisfied_at = ? WHERE session_token = 'tok-sat'`)
      .bind(new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString())
      .run();
    await openStepUpChallenge({ env, sessionToken: "tok-live", userId: "u1", reasons: [], requestPath: "/p" });
    await cleanupStepUpChallenges(env, new Date());
    const tokens = await db.prepare(`SELECT session_token FROM session_step_up_requirements`).bind().all<{ session_token: string }>();
    expect(tokens.results.map((r) => r.session_token)).toEqual(["tok-live"]);
  });
});

describe("second-factor availability", () => {
  test("better-auth 2FA, hardware tokens, and Duo config enumerate methods", async () => {
    const db = await setup();
    db.exec(`
      CREATE TABLE "user" (id TEXT PRIMARY KEY, "twoFactorEnabled" INTEGER);
      INSERT INTO "user" (id, "twoFactorEnabled") VALUES ('u-totp', 1);
      INSERT INTO "user" (id, "twoFactorEnabled") VALUES ('u-none', 0);
      INSERT INTO "user" (id, "twoFactorEnabled") VALUES ('u-otp', 1);
      CREATE TABLE "twoFactor" (id TEXT PRIMARY KEY, userId TEXT, verified INTEGER);
      INSERT INTO "twoFactor" (id, userId, verified) VALUES ('t1', 'u-totp', 1);
    `);
    await db.prepare(`INSERT INTO mfa_hotp_tokens (id, user_id, label, secret_base32, counter, created_at)
                      VALUES ('h1', 'u-none', 'YubiKey', 'sealed', 0, '2026-01-01T00:00:00Z')`).bind().run();

    const duoEnv = { DUO_IKEY: "DIK", DUO_SKEY: "s", DUO_API_HOSTNAME: "api.duo.test" } as unknown as Env;
    // With Duo configured, every user can complete a push; without it, only
    // the enrolled TOTP account has methods.
    const duoString = { DUO_IKEY: "DIK", DUO_SKEY: "s", DUO_API_HOSTNAME: "api.duo.test" } as unknown as Record<string, string>;
    expect(await usableSecondFactors(envWith(db, duoString), "u-none")).toEqual(["hotp", "duo_push"]);
    expect(await usableSecondFactors(envWith(db, duoString), "u-totp"))
      .toEqual(["totp", "otp", "backup_code", "duo_push"]);

    // Without Duo configured: hardware token still usable; nothing for u2.
    const plain = await usableSecondFactors(envWith(db), "u-none");
    expect(plain).toEqual(["hotp"]);
    expect(await usableSecondFactors(envWith(db), "u-totp")).toEqual(["totp", "otp", "backup_code"]);
    // Email/SMS codes alone (no authenticator secret) offer neither TOTP nor backup codes.
    expect(await usableSecondFactors(envWith(db), "u-otp")).toEqual(["otp"]);
    expect(await usableSecondFactors(envWith(db), "u-missing")).toEqual([]);
    // The administrator can switch a method off for everyone.
    expect(await usableSecondFactors(envWith(db, { MFA_ALLOW_TOTP: "off", MFA_ALLOW_OTP: "off" }), "u-totp")).toEqual(["backup_code"]);
  });

  test("the OPAQUE gate's step-up branch is challenge-eligible only with a factor", async () => {
    const db = await setup();
    db.exec(`
      CREATE TABLE "user" (id TEXT PRIMARY KEY, "twoFactorEnabled" INTEGER);
      INSERT INTO "user" (id, "twoFactorEnabled") VALUES ('u-totp', 1);
      INSERT INTO "user" (id, "twoFactorEnabled") VALUES ('u-none', 0);
    `);
    const { stepUpOutcome } = await import("../../src/auth/opaque-login");
    const env = envWith(db);
    const withFactor = await stepUpOutcome(env, "u-totp", ["impossible_travel"]);
    expect(withFactor).toEqual({ allowed: true, action: "step_up", reasons: ["impossible_travel"] });
    const withoutFactor = await stepUpOutcome(env, "u-none", ["impossible_travel"]);
    expect(withoutFactor.allowed).toBe(false);
    expect(withoutFactor.action).toBe("deny");
    expect((withoutFactor as { reasons: string[] }).reasons).toContain("no_second_factor");
  });
});
