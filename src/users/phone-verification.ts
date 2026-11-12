/**
 * Proving that a phone number is the person's own: a six-digit code sent by SMS
 * to the number saved on the account, entered while signed in. The number is
 * then marked verified, which is what lets it receive second-factor codes.
 *
 * This is deliberately not the better-auth phone-number plugin's flow: that
 * one signs the caller in when the code is right, which would make a text
 * message a way around the password and the second factor. These endpoints
 * only ever change the signed-in account's own verified flag.
 */

import type { Env } from "../env";
import { sendSmsCode } from "../mfa/otp-senders";
import { smsAvailable } from "../sms/provider";

const CODE_TTL_MS = 10 * 60_000;
const RESEND_AFTER_MS = 60_000;
const MAX_SENDS_PER_HOUR = 5;
const MAX_ATTEMPTS = 5;

async function keyedHash(env: Env, value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`phone-verification:${value}`));
  return [...new Uint8Array(signature)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sameString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export type SendOutcome =
  | { ok: true; expiresInSeconds: number }
  | { ok: false; reason: "no_number" | "already_verified" | "unavailable" | "too_soon" | "too_many" | "delivery_failed"; retryAfterSeconds?: number };

export async function sendPhoneCode(env: Env, userId: string): Promise<SendOutcome> {
  const user = await env.DB.prepare('SELECT "phoneNumber" AS phone, "phoneNumberVerified" AS verified FROM "user" WHERE id = ?')
    .bind(userId).first<{ phone: string | null; verified: number | null }>();
  if (!user?.phone) return { ok: false, reason: "no_number" };
  if (user.verified === 1) return { ok: false, reason: "already_verified" };
  if (!smsAvailable(env)) return { ok: false, reason: "unavailable" };

  const now = Date.now();
  const open = await env.DB.prepare("SELECT phone, sent_at AS sentAt, window_start AS windowStart, sends_in_window AS sends FROM phone_verifications WHERE user_id = ?")
    .bind(userId).first<{ phone: string; sentAt: string; windowStart: string; sends: number }>();
  let windowStart = new Date(now).toISOString();
  let sends = 1;
  if (open) {
    const sinceLast = now - Date.parse(open.sentAt);
    if (sinceLast < RESEND_AFTER_MS) return { ok: false, reason: "too_soon", retryAfterSeconds: Math.ceil((RESEND_AFTER_MS - sinceLast) / 1000) };
    if (now - Date.parse(open.windowStart) < 60 * 60_000) {
      if (open.sends >= MAX_SENDS_PER_HOUR) return { ok: false, reason: "too_many" };
      windowStart = open.windowStart;
      sends = open.sends + 1;
    }
  }
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, "0");
  await env.DB.prepare(
    `INSERT INTO phone_verifications (user_id, phone, code_hash, attempts, sent_at, expires_at, window_start, sends_in_window)
     VALUES (?, ?, ?, 0, ?, ?, ?, ?)
     ON CONFLICT (user_id) DO UPDATE SET phone = excluded.phone, code_hash = excluded.code_hash, attempts = 0, sent_at = excluded.sent_at,
       expires_at = excluded.expires_at, window_start = excluded.window_start, sends_in_window = excluded.sends_in_window`,
  ).bind(userId, user.phone, await keyedHash(env, `${userId}:${user.phone}:${code}`), new Date(now).toISOString(), new Date(now + CODE_TTL_MS).toISOString(), windowStart, sends).run();
  try {
    await sendSmsCode(env, { to: user.phone, code });
  } catch {
    await env.DB.prepare("DELETE FROM phone_verifications WHERE user_id = ?").bind(userId).run().catch(() => null);
    return { ok: false, reason: "delivery_failed" };
  }
  return { ok: true, expiresInSeconds: CODE_TTL_MS / 1000 };
}

export type VerifyOutcome =
  | { ok: true }
  | { ok: false; reason: "no_code" | "expired" | "wrong" | "too_many_attempts"; attemptsLeft?: number };

export async function verifyPhoneCode(env: Env, userId: string, code: string): Promise<VerifyOutcome> {
  const row = await env.DB.prepare("SELECT phone, code_hash AS hash, attempts, expires_at AS expiresAt FROM phone_verifications WHERE user_id = ?")
    .bind(userId).first<{ phone: string; hash: string; attempts: number; expiresAt: string }>();
  if (!row) return { ok: false, reason: "no_code" };
  const user = await env.DB.prepare('SELECT "phoneNumber" AS phone FROM "user" WHERE id = ?').bind(userId).first<{ phone: string | null }>();
  // A code is for the number it was sent to; changing the number cancels it.
  if (!user?.phone || user.phone !== row.phone) {
    await env.DB.prepare("DELETE FROM phone_verifications WHERE user_id = ?").bind(userId).run();
    return { ok: false, reason: "no_code" };
  }
  if (Date.parse(row.expiresAt) < Date.now()) {
    await env.DB.prepare("DELETE FROM phone_verifications WHERE user_id = ?").bind(userId).run();
    return { ok: false, reason: "expired" };
  }
  if (row.attempts >= MAX_ATTEMPTS) {
    await env.DB.prepare("DELETE FROM phone_verifications WHERE user_id = ?").bind(userId).run();
    return { ok: false, reason: "too_many_attempts" };
  }
  // Count the try before comparing, so a parallel burst cannot get extra guesses.
  await env.DB.prepare("UPDATE phone_verifications SET attempts = attempts + 1 WHERE user_id = ?").bind(userId).run();
  if (!/^[0-9]{6}$/.test(code) || !sameString(await keyedHash(env, `${userId}:${row.phone}:${code}`), row.hash)) {
    const left = MAX_ATTEMPTS - row.attempts - 1;
    if (left <= 0) {
      await env.DB.prepare("DELETE FROM phone_verifications WHERE user_id = ?").bind(userId).run();
      return { ok: false, reason: "too_many_attempts" };
    }
    return { ok: false, reason: "wrong", attemptsLeft: left };
  }
  // Bind the trusted write to the proved number, even if the profile changed after the read.
  const updated = await env.DB.prepare('UPDATE "user" SET "phoneNumberVerified" = 1, "updatedAt" = ? WHERE id = ? AND "phoneNumber" = ?').bind(new Date().toISOString(), userId, row.phone).run();
  if (updated.meta.changes !== 1) return { ok: false, reason: "no_code" };
  await env.DB.prepare("DELETE FROM phone_verifications WHERE user_id = ? AND phone = ? AND code_hash = ?").bind(userId, row.phone, row.hash).run();
  return { ok: true };
}
