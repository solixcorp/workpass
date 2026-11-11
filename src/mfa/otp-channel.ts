import type { Env } from "../env";

// Bind the channel to the code without storing the low-entropy OTP in plaintext.
async function codeHash(env: Env, userId: string, code: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const bytes = await crypto.subtle.sign("HMAC", key, encoder.encode(JSON.stringify([userId, code])));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function rememberOtpChannel(env: Env, userId: string, code: string, channel: "email" | "sms"): Promise<void> {
  await env.DB.prepare(`INSERT INTO mfa_otp_channels (user_id, code_hash, channel, sent_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, channel = excluded.channel, sent_at = excluded.sent_at`)
    .bind(userId, await codeHash(env, userId, code), channel, new Date().toISOString()).run();
}

export async function otpChannel(env: Env, userId: string, code: string): Promise<"email" | "sms" | undefined> {
  const row = await env.DB.prepare("SELECT channel FROM mfa_otp_channels WHERE user_id = ? AND code_hash = ? AND sent_at >= ?")
    .bind(userId, await codeHash(env, userId, code), new Date(Date.now() - 180_000).toISOString())
    .first<{ channel: string }>().catch(() => null);
  return row?.channel === "email" || row?.channel === "sms" ? row.channel : undefined;
}
