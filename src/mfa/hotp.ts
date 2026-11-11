/**
 * HOTP (RFC 4226) verification for hardware OTP tokens that we manage
 * ourselves, independent of Duo: the operator attaches the token's base32
 * secret to a user, and the user's generated passcode is verified against a
 * small counter lookahead window (replay-safe by counter advancement).
 */

import { looksSealed, sealString, unsealString } from "../crypto/sealed";
import type { Env } from "../env";

const HOTP_LOOKAHEAD = 5;
const HOTP_DIGITS = 6;

function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let accumulator = 0;
  const output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("The token secret is not valid base32");
    accumulator = (accumulator << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((accumulator >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  // Trailing bits (< 8) are an encoding artifact of non-canonical values, not
  // secret material; dropping them matches reference decoders (RFC 4648).
  return new Uint8Array(output);
}

function hotpCode(secret: Uint8Array, counter: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
  const rawKey = new ArrayBuffer(secret.length);
  new Uint8Array(rawKey).set(secret);
  return crypto.subtle
    .importKey("raw", rawKey, { name: "HMAC", hash: "SHA-1" }, false, ["sign"])
    .then((key) => crypto.subtle.sign("HMAC", key, counterBytes.buffer))
    .then((mac) => {
      const bytes = new Uint8Array(mac);
      const offset = bytes[bytes.length - 1]! & 0x0f;
      const binary =
        ((bytes[offset]! & 0x7f) << 24) |
        (bytes[offset + 1]! << 16) |
        (bytes[offset + 2]! << 8) |
        bytes[offset + 3]!;
      return String(binary % 1_000_000).padStart(6, "0");
    });
}

export function generateHotpSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  // RFC 4648 base32 (unpadded): 20 bytes = 160 bits = exactly 32 characters.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  let accumulator = 0;
  let bits = 0;
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(accumulator >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

export async function hotpVerify(env: Env, userId: string, code: string): Promise<{ verified: boolean; tokenId: string | null }> {
  if (!/^\d{6}$/.test(code)) return { verified: false, tokenId: null };
  const rows = await env.DB.prepare(
    `SELECT id, secret_base32 AS secretB32, counter FROM mfa_hotp_tokens WHERE user_id = ? AND verified = 1 ORDER BY created_at ASC LIMIT 10`,
  ).bind(userId).all<{ id: string; secretB32: string; counter: number }>();
  let secret: Uint8Array | null = null;
  for (const row of rows.results) {
    // Sealed envelopes open with the per-user AAD; legacy plaintext rows are
    // lazily migrated on the first successful use and re-sealed immediately.
    let secretB32: string;
    try {
      secretB32 = looksSealed(row.secretB32)
        ? await unsealString(env, row.secretB32, `mfa_hotp_token:${userId}`)
        : row.secretB32;
    } catch {
      continue;
    }
    try {
      secret = base32Decode(secretB32);
    } catch {
      continue;
    }
    if (!looksSealed(row.secretB32)) {
      try {
        const sealed = await sealString(env, secretB32, `mfa_hotp_token:${userId}`);
        await env.DB.prepare("UPDATE mfa_hotp_tokens SET secret_base32 = ? WHERE id = ? AND user_id = ?")
          .bind(sealed, row.id, userId).run();
      } catch {
        // Migration is best-effort; verification still proceeds this request.
      }
    }
    if (!secret) continue;
    for (let offset = 0; offset <= HOTP_LOOKAHEAD; offset += 1) {
      const candidate = await hotpCode(secret, row.counter + offset);
      if (candidate === code) {
        const updated = await env.DB.prepare(
          "UPDATE mfa_hotp_tokens SET counter = ? WHERE id = ? AND user_id = ? AND counter = ?",
        ).bind(row.counter + offset + 1, row.id, userId, row.counter).run();
        if (updated.meta.changes === 1) return { verified: true, tokenId: row.id };
        return { verified: false, tokenId: null };
      }
    }
  }
  return { verified: false, tokenId: null };
}

/** Does the user have a verified hardware OTP token? */
export async function userHasHotpToken(env: Env, userId: string): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM mfa_hotp_tokens WHERE user_id = ? AND verified = 1",
  ).bind(userId).first<{ count: number }>();
  return (row?.count ?? 0) > 0;
}

/** First successful code flips a self-enrolled token from pending to verified.
 * Targets one token by id (the enroll response hands it to the confirm step);
 * counter bookkeeping matches the sign-in path. */
export async function hotpEnrollVerify(
  env: Env,
  userId: string,
  tokenId: string,
  code: string,
): Promise<{ verified: boolean; alreadyVerified: boolean; notFound: boolean }> {
  if (!/^\d{6}$/.test(code) || tokenId.length === 0 || tokenId.length > 64) {
    return { verified: false, alreadyVerified: false, notFound: false };
  }
  const row = await env.DB.prepare(
    `SELECT id, secret_base32 AS secretB32, counter, verified FROM mfa_hotp_tokens
     WHERE id = ? AND user_id = ? LIMIT 1`,
  ).bind(tokenId, userId).first<{ id: string; secretB32: string; counter: number; verified: number | null }>();
  if (!row) return { verified: false, alreadyVerified: false, notFound: true };
  let secret: Uint8Array | null = null;
  try {
    if (looksSealed(row.secretB32)) {
      secret = base32Decode(await unsealString(env, row.secretB32, `mfa_hotp_token:${userId}`));
    } else {
      secret = base32Decode(row.secretB32);
      try {
        const sealed = await sealString(env, row.secretB32, `mfa_hotp_token:${userId}`);
        await env.DB.prepare("UPDATE mfa_hotp_tokens SET secret_base32 = ? WHERE id = ? AND user_id = ?")
          .bind(sealed, row.id, userId).run();
      } catch {
        // Migration is best-effort; verification still proceeds this request.
      }
    }
  } catch {
    return { verified: false, alreadyVerified: false, notFound: false };
  }
  if (!secret) return { verified: false, alreadyVerified: false, notFound: false };
  for (let offset = 0; offset <= HOTP_LOOKAHEAD; offset += 1) {
    const candidate = await hotpCode(secret, row.counter + offset);
    if (candidate !== code) continue;
    const updated = await env.DB.prepare(
      "UPDATE mfa_hotp_tokens SET counter = ?, verified = 1 WHERE id = ? AND user_id = ? AND counter = ? AND verified = ?",
    ).bind(row.counter + offset + 1, row.id, userId, row.counter, row.verified).run();
    if (updated.meta.changes === 1) return { verified: true, alreadyVerified: row.verified === 1, notFound: false };
    return { verified: false, alreadyVerified: false, notFound: false };
  }
  return { verified: false, alreadyVerified: false, notFound: false };
}
