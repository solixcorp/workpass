import { sealString, unsealString } from "../crypto/sealed";
import type { Env } from "../env";

/**
 * RS256 signing key for outbound Security Event Tokens (OpenID SSF 1.0).
 * Generated on first use and sealed at rest; the public half is published at
 * /api/ssf/jwks.json so receivers can pin the key. Rotation: generate a new
 * generation, publish both during an overlap, and retire the old one after
 * receivers confirm.
 */

export const SSF_KEY_AAD = "internal-auth:ssf:signing-key";

interface SsfKeyRow {
  generation: number;
  sealed_private_key: string;
  public_jwk: string;
  retired: number;
  created_at: number;
}

export interface SsfKey {
  generation: number;
  privateText: string;
  publicJwk: Record<string, unknown>;
}

let ensured: Promise<void> | null = null;

async function ensureTable(db: D1Database): Promise<void> {
  await db.prepare(`CREATE TABLE IF NOT EXISTS ssf_signing_keys (
    generation INTEGER PRIMARY KEY NOT NULL CHECK (generation = 1),
    sealed_private_key TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    retired INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`).run();
}

/** Single-generation key kept deliberately small; rotation is a destructive
 * re-enrollment for receivers, so it stays an operator action. */
export async function ensureSsfSigningKey(env: Env): Promise<SsfKey> {
  ensured ??= (async () => {
    await ensureTable(env.DB);
    const existing = await env.DB.prepare("SELECT generation, sealed_private_key, public_jwk FROM ssf_signing_keys WHERE generation = 1")
      .bind().first<SsfKeyRow>();
    if (!existing) {
      const pair = await crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true, ["sign", "verify"],
      );
      const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
      const publicJwk = { kty: privateJwk.kty, n: privateJwk.n, e: privateJwk.e, alg: "RS256", kid: "ssf-1", use: "sig" };
      const sealed = await sealString(env, JSON.stringify(privateJwk), SSF_KEY_AAD);
      const result = await env.DB.prepare(
        "INSERT INTO ssf_signing_keys (generation, sealed_private_key, public_jwk, retired, created_at) VALUES (1, ?, ?, 0, ?)",
      ).bind(sealed, JSON.stringify(publicJwk), Date.now()).run();
      if (!result.success || result.meta?.changes !== 1) throw new Error("SSF signing key storage failed");
    }
  })();
  await ensured;
  const row = await env.DB.prepare("SELECT generation, sealed_private_key, public_jwk FROM ssf_signing_keys WHERE generation = 1")
    .bind().first<SsfKeyRow>();
  if (!row) throw new Error("SSF signing key unavailable");
  return { generation: row.generation, privateText: await unsealString(env, row.sealed_private_key, SSF_KEY_AAD), publicJwk: JSON.parse(row.public_jwk) as Record<string, unknown> };
}

export async function importSsfPrivateKey(privateText: string): Promise<CryptoKey> {
  const jwk = JSON.parse(privateText) as JsonWebKey;
  return crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}
