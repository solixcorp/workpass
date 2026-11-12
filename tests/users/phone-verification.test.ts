import { describe, expect, test } from "bun:test";
import { createTestD1 } from "../test-d1";
import { verifyPhoneCode } from "../../src/users/phone-verification";
import type { Env } from "../../src/env";

async function fixture() {
  const { db, sqlite } = createTestD1();
  sqlite.exec(`CREATE TABLE "user" (id TEXT PRIMARY KEY, "phoneNumber" TEXT, "phoneNumberVerified" INTEGER, "updatedAt" TEXT);
    CREATE TABLE phone_verifications (user_id TEXT PRIMARY KEY, phone TEXT, code_hash TEXT, attempts INTEGER, expires_at TEXT);
    INSERT INTO "user" VALUES ('u1', '+100', 0, '');`);
  const secret = "phone-test-secret";
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("phone-verification:u1:+100:123456"));
  const hash = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  await db.prepare("INSERT INTO phone_verifications VALUES (?, ?, ?, 0, ?)").bind("u1", "+100", hash, new Date(Date.now() + 60_000).toISOString()).run();
  return { db, sqlite, env: { DB: db, AUTH_SECRET: secret } as Env };
}

describe("phone verification write binding", () => {
  test("matching phone is verified and its challenge consumed", async () => {
    const { env, db } = await fixture();
    expect(await verifyPhoneCode(env, "u1", "123456")).toEqual({ ok: true });
    expect(await db.prepare('SELECT "phoneNumberVerified" AS verified FROM "user"').first()).toEqual({ verified: 1 });
    expect(await db.prepare("SELECT * FROM phone_verifications").first()).toBeNull();
  });

  test("a concurrent profile change cannot transfer verification or consume the challenge", async () => {
    const { env, db, sqlite } = await fixture();
    let intercepted = false;
    const wrapped = { ...db, prepare(sql: string) {
      if (sql.startsWith('UPDATE "user" SET "phoneNumberVerified"')) {
        intercepted = true;
        sqlite.exec('UPDATE "user" SET "phoneNumber" = \'+200\', "phoneNumberVerified" = 0 WHERE id = \'u1\'');
      }
      return db.prepare(sql);
    } } as D1Database;
    expect(await verifyPhoneCode({ ...env, DB: wrapped }, "u1", "123456")).toEqual({ ok: false, reason: "no_code" });
    expect(intercepted).toBe(true);
    expect(await db.prepare('SELECT "phoneNumber" AS phone, "phoneNumberVerified" AS verified FROM "user"').first()).toEqual({ phone: "+200", verified: 0 });
    expect(await db.prepare("SELECT phone, attempts FROM phone_verifications").first()).toEqual({ phone: "+100", attempts: 1 });
  });

  test("a code for a previously changed phone is rejected", async () => {
    const { env, db } = await fixture();
    await db.prepare('UPDATE "user" SET "phoneNumber" = ?').bind("+200").run();
    expect(await verifyPhoneCode(env, "u1", "123456")).toEqual({ ok: false, reason: "no_code" });
    expect(await db.prepare('SELECT "phoneNumberVerified" AS verified FROM "user"').first()).toEqual({ verified: 0 });
  });
});
