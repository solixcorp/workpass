/**
 * OPAQUE (RFC 9807 / 9380) server orchestration over @cloudflare/opaque-ts:
 * the wire carries only protocol evidence — the password NEVER leaves the
 * browser and the server stores no password, no password hash, and no
 * password-derived value.
 *
 * Server material:
 * - OPRF seed: HKDF-derived from OPAQUE_MASTER_KEY (deterministic, stable).
 * - AKE keypair: generated on first use, persisted SEALED (XChaCha20) in D1.
 * - Credential records: stored SEALED with the per-user AAD; the envelope
 *   inside the record is itself password-protected by the protocol.
 */

import type { Context } from "hono";
import { getOpaqueConfig, OpaqueID, OpaqueServer, type AKEExportKeyPair } from "@cloudflare/opaque-ts";
import type { Env } from "../env";
import { sealString, unsealString } from "../crypto/sealed";

export type OpaqueConfigInstance = ReturnType<typeof getOpaqueConfig>;

let cachedConfig: OpaqueConfigInstance | null = null;

export function opaqueConfig(): OpaqueConfigInstance {
  cachedConfig ??= getOpaqueConfig(OpaqueID.OPAQUE_P256);
  return cachedConfig;
}

export function opaqueMasterKey(env: Env): Uint8Array {
  const source = (env.OPAQUE_MASTER_KEY ?? "").trim();
  if (!source) throw new Error("OPAQUE_MASTER_KEY must be configured");
  const bytes = base64Decode(source.replace(/-/g, "+").replace(/_/g, "/"));
  if (bytes.length !== 32) throw new Error("OPAQUE_MASTER_KEY must decode to 32 bytes");
  return bytes;
}

async function hkdfBytes(key: Uint8Array, info: string, length: number): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", key.buffer as ArrayBuffer, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
    imported,
    length * 8,
  );
  return new Uint8Array(bits);
}

export async function opaqueOprfSeed(env: Env): Promise<number[]> {
  const bytes = await hkdfBytes(opaqueMasterKey(env), "internal-auth:opaque:oprf-seed:v1", 32);
  return Array.from(bytes);
}

/** Does the persistent server AKE keypair exist (sealed) in the database? */
async function loadSealedAke(env: Env): Promise<string | null> {
  const row = await env.DB.prepare("SELECT material FROM opaque_server_material WHERE id = ?")
    .bind("ake")
    .first<{ material: string }>();
  return row?.material ?? null;
}

export async function opaqueServer(env: Env): Promise<{ server: OpaqueServer; cleanup: () => Promise<void> }> {
  const config = opaqueConfig();
  const seed = await opaqueOprfSeed(env);
  const serverIdentity = new URL(env.AUTH_BASE_URL).origin;
  const existing = await loadSealedAke(env);
  let keypair: AKEExportKeyPair;
  let created = false;
  if (existing) {
    const json = JSON.parse(await unsealString(env, existing, "opaque_server_ake")) as
      { private_key: number[]; public_key: number[] };
    keypair = json;
  } else {
    const generated = await config.ake.generateAuthKeyPair();
    const sealed = await sealString(
      env,
      JSON.stringify({ private_key: generated.private_key, public_key: generated.public_key }),
      "opaque_server_ake",
    );
    await env.DB.prepare(
      "INSERT INTO opaque_server_material (id, material, created_at) VALUES (?, ?, ?) ON CONFLICT (id) DO NOTHING",
    ).bind("ake", sealed, new Date().toISOString()).run();
    created = true;
    keypair = generated;
  }
  const server = new OpaqueServer(config, seed, keypair, serverIdentity);
  return { server, cleanup: async () => { void created; } };
}

export function base64Encode(bytes: Uint8Array | number[]): string {
  const view = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64Decode(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/** Canonical credential identifier: the user's lowercased email. */
export function opaqueIdentityFor(email: string): string {
  return email.toLowerCase();
}

export function opaqueBadRequest(context: Context<{ Bindings: Env }>, detail: string, status: 400 | 401 | 403 | 429 | 503 = 400): Response {
  return context.json({ error: detail }, status);
}
