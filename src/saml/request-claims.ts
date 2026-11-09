import type { Env } from "../env";

/**
 * Claim an already cryptographically verified AuthnRequest once per SP.
 * The caller must validate signature, issuer, destination and freshness first.
 * A claim does not by itself authenticate a user or authorize an assertion.
 */
export async function claimVerifiedSamlRequest(input: {
  env: Env;
  providerId: string;
  requestId: string;
  expiresAt: Date;
}): Promise<boolean> {
  const now = new Date();
  if (
    !input.providerId || input.providerId.length > 128 ||
    !input.requestId || input.requestId.length > 256 ||
    /[\u0000-\u001f\u007f]/.test(input.requestId) ||
    !Number.isFinite(input.expiresAt.getTime()) ||
    input.expiresAt.getTime() <= now.getTime() ||
    input.expiresAt.getTime() > now.getTime() + 10 * 60_000
  ) {
    throw new Error("Invalid SAML request claim");
  }
  const results = await input.env.DB.batch([
    input.env.DB.prepare("DELETE FROM saml_request_claims WHERE expires_at <= ?").bind(now.toISOString()),
    input.env.DB.prepare(
      `INSERT OR IGNORE INTO saml_request_claims (provider_id, request_id, claimed_at, expires_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(input.providerId, input.requestId, now.toISOString(), input.expiresAt.toISOString()),
  ]);
  return results[1]?.meta.changes === 1;
}

/** The scheduled handler may run before the SAML migration has been applied. */
export async function cleanupSamlRequestClaims(env: Env, now = new Date()): Promise<void> {
  const table = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'saml_request_claims'",
  ).first<{ name: string }>();
  if (!table) return;
  await env.DB.prepare("DELETE FROM saml_request_claims WHERE expires_at <= ?")
    .bind(now.toISOString())
    .run();
}
