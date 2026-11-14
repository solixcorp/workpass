import { beforeAll, describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { ensureApplicationTables } from "../../src/db/schema";
import { loadAppAccessPolicy, upsertAppAccessPolicy } from "../../src/access/policies";
import { getSessionMfaProof, recordSessionMfaProof, sessionSatisfiesRequireMfa } from "../../src/mfa/second-factor";
import { rememberOtpChannel, otpChannel } from "../../src/mfa/otp-channel";
import { appMfaChallenge } from "../../src/security/step-up";
import { sendOtpWithFallback } from "../../src/mfa/otp-senders";
import mod from "../../src/index";

describe("application MFA methods", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "test-secret-for-app-mfa-0123456789", MFA_SMS_WEBHOOK_URL: "https://sms.test", INVITATION_EMAIL_WEBHOOK_URL: "https://mail.test" } as Env;
  const base = { subject: "app:test", allowedMethods: "password,passkey", sessionTtlSeconds: null, bypassWindowSeconds: 0, enforcementMode: "enforce" as const, requireMfa: true, groups: [], requiredAccount: null };
  const session = { user: { id: "user1" }, session: { token: "token1" } };
  beforeAll(async () => {
    await ensureApplicationTables(env);
    await db.prepare('CREATE TABLE "user" (id TEXT PRIMARY KEY, email TEXT, "phoneNumber" TEXT, "phoneNumberVerified" INTEGER, "twoFactorEnabled" INTEGER)').run();
    await db.prepare('CREATE TABLE "twoFactor" (userId TEXT, verified INTEGER)').run();
    await db.prepare('INSERT INTO "user" VALUES (?, ?, NULL, 0, 1)').bind("user1", "u@example.test").run();
    await db.prepare('INSERT INTO "twoFactor" VALUES (?, 1)').bind("user1").run();
  });
  test("migration defaults, policy round trip and validation", async () => {
    await upsertAppAccessPolicy(env, base, "admin");
    expect((await loadAppAccessPolicy(env, base.subject))?.mfaMethods).toEqual([]);
    await upsertAppAccessPolicy(env, { ...base, mfaMethods: ["totp", "email"] }, "admin");
    expect((await loadAppAccessPolicy(env, base.subject))?.mfaMethods).toEqual(["totp", "email"]);
    await expect(upsertAppAccessPolicy(env, { ...base, mfaMethods: ["otp"] }, "admin")).rejects.toThrow();
    await expect(upsertAppAccessPolicy({ ...env, MFA_ALLOW_TOTP: "off" }, { ...base, mfaMethods: ["totp"] }, "admin")).rejects.toThrow();
  });
  test("proofs require matching methods and accumulate without duplicates", async () => {
    expect(await sessionSatisfiesRequireMfa(env, session, ["totp"])).toBe(false);
    expect(await recordSessionMfaProof(env, "token1", "user1")).toBe(true);
    expect(await sessionSatisfiesRequireMfa(env, session)).toBe(true);
    expect(await sessionSatisfiesRequireMfa(env, session, ["totp"])).toBe(false);
    await recordSessionMfaProof(env, "token1", "user1", "totp");
    expect(await sessionSatisfiesRequireMfa(env, session, ["totp"])).toBe(true);
    expect(await sessionSatisfiesRequireMfa(env, session, ["sms"])).toBe(false);
    await recordSessionMfaProof(env, "token1", "user1", "passkey");
    await recordSessionMfaProof(env, "token1", "user1", "totp");
    expect((await getSessionMfaProof(env, "token1"))?.methods).toEqual(["unknown", "totp", "passkey"]);
    expect(await sessionSatisfiesRequireMfa(env, session, ["passkey"])).toBe(true);
  });
  test("OTP channel is bound to the verified code", async () => {
    await rememberOtpChannel(env, "user1", "123456", "email");
    expect(await otpChannel(env, "user1", "123456")).toBe("email");
    await rememberOtpChannel(env, "user1", "654321", "sms");
    expect(await otpChannel(env, "user1", "123456")).toBeUndefined();
    expect(await otpChannel(env, "user1", "654321")).toBe("sms");
  });
  test("actual OTP delivery records email and SMS channels", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch;
    try {
      const deliveryEnv = { ...env, MFA_OTP_EMAIL_WEBHOOK_URL: "https://mail.test", AUTH_BASE_URL: "http://localhost" };
      await sendOtpWithFallback(deliveryEnv, { userId: "user1", email: "u@example.test", otp: "111111" });
      expect(await otpChannel(env, "user1", "111111")).toBe("email");
      await db.prepare('UPDATE "user" SET "phoneNumber" = ?, "phoneNumberVerified" = 1 WHERE id = ?').bind("01012345678", "user1").run();
      await sendOtpWithFallback(deliveryEnv, { userId: "user1", email: "u@example.test", otp: "222222" });
      expect(await otpChannel(env, "user1", "222222")).toBe("sms");
    } finally {
      globalThis.fetch = original;
      await db.prepare('UPDATE "user" SET "phoneNumber" = NULL, "phoneNumberVerified" = 0 WHERE id = ?').bind("user1").run();
    }
  });
  test("challenge intersects enrolled methods and denies impossible requirements", async () => {
    const offered = await appMfaChallenge(env, "user1", ["totp", "sms"]);
    expect((await offered.json() as { methods: string[] }).methods).toEqual(["totp"]);
    const denied = await appMfaChallenge(env, "user1", ["sms"]);
    expect(denied.status).toBe(403);
    expect((await denied.json() as { requiredMethods: string[] }).requiredMethods).toEqual(["sms"]);
  });
  test("anonymous admin access is rejected", async () => {
    const isolatedEnv = { ...env, DB: createTestD1().db, AUTH_BASE_URL: "http://localhost", ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789" };
    const execution = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
    await mod.fetch(new Request("http://localhost/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${isolatedEnv.MIGRATION_TOKEN}` } }), isolatedEnv, execution);
    const response = await mod.fetch(new Request("http://localhost/api/admin/app-access-policies"),
      isolatedEnv, execution);
    expect(response.status).toBe(401);
  });
});
