/**
 * Sealed storage: the platform AEAD for sensitive material at rest (MFA token
 * secrets, OPAQUE server material and credential records, future credential
 * payloads).
 *
 * Two approved algorithms are supported, selected by envelope version and by
 * `SEALED_STORAGE_CIPHER` (the WRITE cipher):
 *   v1 <nonce>.<ciphertext+tag> — XChaCha20-Poly1305 via @noble/ciphers,
 *                                 24-byte CSPRNG nonce (the original cipher,
 *                                 kept for reading every existing envelope).
 *   v2 <nonce>.<ciphertext+tag> — AES-256-GCM via WebCrypto, 12-byte CSPRNG
 *                                 nonce, 96-bit IV + 128-bit tag per
 *                                 NIST SP 800-38D. This is the FIPS-aligned
 *                                 selection for deployments that need to run
 *                                 on approved-algorithm paths only.
 *
 * Reads are version-driven: a v1 envelope always opens with XChaCha and a v2
 * envelope with AES-GCM, independent of the configured write cipher, so
 * switching between them never strands existing rows. Rows re-seal lazily
 * under their callers' custody.
 *
 * Configuration (fail-closed): AEAD_SEALING_KEY must be a 32-byte key,
 * base64-encoded. SEALED_STORAGE_CIPHER defaults to xchacha20poly1305 and may
 * be set to aes256gcm; every unknown cipher, key length, or format deviation
 * throws — never store plaintext as a fallback.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import type { Env } from "../env";

export const SUPPORTED_SEALED_STORAGE_CIPHERS = ["xchacha20poly1305", "aes256gcm"] as const;
export type SealedStorageCipher = (typeof SUPPORTED_SEALED_STORAGE_CIPHERS)[number];

/** Envelope versions by write cipher; reads key off the version, not the config. */
const VERSION_BY_CIPHER: Record<SealedStorageCipher, string> = {
  xchacha20poly1305: "v1",
  aes256gcm: "v2",
};
const CIPHER_BY_VERSION: Record<string, SealedStorageCipher> = {
  v1: "xchacha20poly1305",
  v2: "aes256gcm",
};

const XCHACHA_NONCE_BYTES = 24;
const AES_NONCE_BYTES = 12;
const KEY_BYTES = 32;

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
    throw new Error(`AEAD_SEALING_KEY must decode to ${KEY_BYTES} bytes`);
  }
  cachedKey = raw;
  cachedKeySource = source;
  return raw;
}

function writeCipherFor(env: Env): SealedStorageCipher {
  const configured = (env.SEALED_STORAGE_CIPHER ?? "xchacha20poly1305").trim();
  if (!(SUPPORTED_SEALED_STORAGE_CIPHERS as readonly string[]).includes(configured)) {
    throw new Error(
      `SEALED_STORAGE_CIPHER "${configured}" is not supported; use one of ${SUPPORTED_SEALED_STORAGE_CIPHERS.join(", ")}`,
    );
  }
  return configured as SealedStorageCipher;
}

function nonceBytesFor(cipher: SealedStorageCipher): number {
  return cipher === "aes256gcm" ? AES_NONCE_BYTES : XCHACHA_NONCE_BYTES;
}

/** SubtleCrypto wants a real ArrayBuffer; copy views so byte offsets are honored. */
function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

async function aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", toArrayBuffer(key), { name: "AES-GCM" }, false, ["encrypt"]);
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(aad), tagLength: 128 },
    imported,
    toArrayBuffer(plaintext),
  );
  return new Uint8Array(sealed);
}

async function aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", toArrayBuffer(key), { name: "AES-GCM" }, false, ["decrypt"]);
  const opened = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(aad), tagLength: 128 },
    imported,
    toArrayBuffer(ciphertext),
  );
  return new Uint8Array(opened);
}

/** Does a stored value look like a sealed envelope (vs. legacy plaintext)? */
export function looksSealed(value: string): boolean {
  const parts = value.trim().split(".");
  if (parts.length !== 3) return false;
  if (parts[0] === "v1") return parts[1]!.length === 32 && parts[2]!.length % 4 !== 1;
  if (parts[0] === "v2") return parts[1]!.length === 16 && parts[2]!.length % 4 !== 1;
  return false;
}

/** Seal bytes into the versioned base64url envelope with the configured write cipher. */
export async function sealBytes(env: Env, plaintext: Uint8Array, aad = "internal-auth:v1"): Promise<string> {
  const cipher = writeCipherFor(env);
  const version = VERSION_BY_CIPHER[cipher];
  const key = sealingKey(env);
  const nonce = crypto.getRandomValues(new Uint8Array(nonceBytesFor(cipher)));
  const aadBytes = new TextEncoder().encode(aad);
  const sealed = cipher === "aes256gcm"
    ? await aesGcmEncrypt(key, nonce, aadBytes, plaintext)
    : xchacha20poly1305(key, nonce, aadBytes).encrypt(plaintext);
  return `${version}.${bytesToBase64Url(nonce)}.${bytesToBase64Url(sealed)}`;
}

/** Open a sealed envelope; throws on tampering or any format deviation. */
export async function unsealBytes(env: Env, envelope: string, aad = "internal-auth:v1"): Promise<Uint8Array> {
  const parts = envelope.trim().split(".");
  if (parts.length !== 3 || !(parts[0] in CIPHER_BY_VERSION)) {
    throw new Error("Sealed envelope is not a v1/v2 envelope");
  }
  const version = parts[0]!;
  const cipher = CIPHER_BY_VERSION[version]!;
  const nonce = base64ToBytes(parts[1]!);
  const ciphertext = base64ToBytes(parts[2]!);
  const expectedNonce = nonceBytesFor(cipher);
  if (nonce.length !== expectedNonce) {
    throw new Error(`Sealed envelope ${version} nonce has an invalid length`);
  }
  const key = sealingKey(env);
  const opened = cipher === "aes256gcm"
    ? await aesGcmDecrypt(key, nonce, new TextEncoder().encode(aad), ciphertext)
    : xchacha20poly1305(key, nonce, new TextEncoder().encode(aad)).decrypt(ciphertext);
  return opened;
}

export function sealString(env: Env, plaintext: string, aad?: string): Promise<string> {
  return sealBytes(env, new TextEncoder().encode(plaintext), aad);
}

export function unsealString(env: Env, envelope: string, aad?: string): Promise<string> {
  return unsealBytes(env, envelope, aad).then((bytes) => new TextDecoder().decode(bytes));
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
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
