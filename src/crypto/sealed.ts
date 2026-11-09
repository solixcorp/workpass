/**
 * Sealed storage: the platform AEAD for sensitive material at rest (MFA token
 * secrets, future credential payloads), chosen by live workerd comparison:
 * XChaCha20-Poly1305 via @noble/ciphers (see tests/aead-cipher-swap.test.ts).
 *
 * Envelope format (versioned, base64url):
 *   v1.<nonce>.<ciphertext+tag>     — XChaCha20-Poly1305, 24-byte CSPRNG nonce
 *
 * Configuration (fail-closed): AEAD_SEALING_KEY must be a 32-byte key,
 * base64-encoded. SEALED_STORAGE_CIPHER defaults to and currently only allows
 * "xchacha20poly1305". Every cipher, key length, and format deviation throws —
 * never store plaintext as a fallback.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import type { Env } from "../env";

export const SUPPORTED_SEALED_STORAGE_CIPHERS = ["xchacha20poly1305"] as const;
export type SealedStorageCipher = (typeof SUPPORTED_SEALED_STORAGE_CIPHERS)[number];

const NONCE_BYTES = 24;
const KEY_BYTES = 32; // XChaCha20-Poly1305 (IETF) key size
const ENVELOPE_VERSION = "v1";

let cachedKey: Uint8Array | null = null;
let cachedKeySource: string | null = null;

function sealingKey(env: Env): Uint8Array {
  const source = env.AEAD_SEALING_KEY ?? "";
  if (!source) throw new Error("AEAD_SEALING_KEY must be configured for sealed storage");
  if (cachedKey && cachedKeySource === source) return cachedKey;
  const normalized = source.trim();
  let raw: Uint8Array;
  try {
    raw = base64ToBytes(normalized);
  } catch {
    throw new Error("AEAD_SEALING_KEY must be base64");
  }
  if (raw.length !== KEY_BYTES) {
    throw new Error(`AEAD_SEALING_KEY must decode to ${KEY_BYTES} bytes for xchacha20poly1305`);
  }
  cachedKey = raw;
  cachedKeySource = source;
  return raw;
}

function cipherFor(env: Env): SealedStorageCipher {
  const configured = (env.SEALED_STORAGE_CIPHER ?? "xchacha20poly1305").trim();
  if (!(SUPPORTED_SEALED_STORAGE_CIPHERS as readonly string[]).includes(configured)) {
    throw new Error(
      `SEALED_STORAGE_CIPHER "${configured}" is not supported; use one of ${SUPPORTED_SEALED_STORAGE_CIPHERS.join(", ")}`,
    );
  }
  return "xchacha20poly1305";
}

/** Seal bytes into the versioned base64url envelope. */
export async function sealBytes(env: Env, plaintext: Uint8Array, aad = "internal-auth:v1"): Promise<string> {
  const cipher = cipherFor(env);
  if (cipher !== "xchacha20poly1305") throw new Error("Unsupported sealed storage cipher");
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const envelope = xchacha20poly1305(sealingKey(env), nonce, new TextEncoder().encode(aad)).encrypt(plaintext);
  return `${ENVELOPE_VERSION}.${bytesToBase64Url(nonce)}.${bytesToBase64Url(envelope)}`;
}

/** Open a sealed envelope; throws on tampering or any format deviation. */
export async function unsealBytes(env: Env, envelope: string, aad = "internal-auth:v1"): Promise<Uint8Array> {
  const parts = envelope.trim().split(".");
  if (parts.length !== 3 || parts[0] !== ENVELOPE_VERSION) {
    throw new Error("Sealed envelope is not a v1 envelope");
  }
  const nonce = base64ToBytes(parts[1]!);
  const ciphertext = base64ToBytes(parts[2]!);
  if (nonce.length !== NONCE_BYTES) throw new Error("Sealed envelope nonce has an invalid length");
  const cipher = cipherFor(env);
  if (cipher !== "xchacha20poly1305") throw new Error("Unsupported sealed storage cipher");
  const opened = xchacha20poly1305(sealingKey(env), nonce, new TextEncoder().encode(aad)).decrypt(ciphertext);
  return opened;
}

export function sealString(env: Env, plaintext: string, aad?: string): Promise<string> {
  return sealBytes(env, new TextEncoder().encode(plaintext), aad);
}

export function unsealString(env: Env, envelope: string, aad?: string): Promise<string> {
  return unsealBytes(env, envelope, aad).then((bytes) => new TextDecoder().decode(bytes));
}

/** Does the stored value look like a v1 sealed envelope (vs. legacy plaintext)? */
export function looksSealed(value: string): boolean {
  const parts = value.trim().split(".");
  return parts.length === 3 && parts[0] === ENVELOPE_VERSION && parts[1]!.length === 32 && parts[2]!.length % 4 !== 1;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64ToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
