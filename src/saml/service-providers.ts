import type { Env } from "../env";

/** Registration data. Enablement is a deliberate administrator action, never automatic. */
export interface SamlServiceProvider {
  id: string;
  entityId: string;
  acsUrl: string;
  signingCertificate: string;
  enabled: boolean;
}

export function validateSamlServiceProvider(input: SamlServiceProvider): void {
  if (
    !input.id || input.id.length > 128 || !input.entityId ||
    input.entityId.length > 2048 || /[\u0000-\u001f\u007f"']/.test(input.entityId)
  ) {
    throw new Error("Invalid SAML service provider identifier");
  }
  let acs: URL;
  try {
    acs = new URL(input.acsUrl);
  } catch {
    throw new Error("Invalid SAML assertion consumer URL");
  }
  if (acs.protocol !== "https:" || acs.username || acs.password || acs.hash) {
    throw new Error("SAML assertion consumer URL must be HTTPS without credentials or fragment");
  }
  if (
    input.signingCertificate.length > 16_384 ||
    !/^-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*$/.test(input.signingCertificate)
  ) {
    throw new Error("SAML signing certificate must be PEM encoded");
  }
}

/** Read registration by immutable local ID; callers must independently enforce authorization. */
export async function getSamlServiceProvider(env: Env, id: string): Promise<SamlServiceProvider | null> {
  const row = await env.DB.prepare(
    `SELECT id, entity_id, acs_url, signing_certificate, enabled
     FROM saml_service_providers WHERE id = ?`,
  ).bind(id).first<{
    id: string;
    entity_id: string;
    acs_url: string;
    signing_certificate: string;
    enabled: number;
  }>();
  if (!row) return null;
  return {
    id: row.id,
    entityId: row.entity_id,
    acsUrl: row.acs_url,
    signingCertificate: row.signing_certificate,
    enabled: row.enabled === 1,
  };
}

/** Look up an enabled registration by its SAML entity ID (untrusted input). */
export async function getEnabledSamlServiceProviderByEntityId(
  env: Env,
  entityId: string,
): Promise<SamlServiceProvider | null> {
  if (!entityId || entityId.length > 2048) return null;
  const row = await env.DB.prepare(
    `SELECT id, entity_id, acs_url, signing_certificate, enabled
     FROM saml_service_providers WHERE entity_id = ? AND enabled = 1`,
  ).bind(entityId).first<{
    id: string;
    entity_id: string;
    acs_url: string;
    signing_certificate: string;
    enabled: number;
  }>();
  if (!row) return null;
  return {
    id: row.id,
    entityId: row.entity_id,
    acsUrl: row.acs_url,
    signingCertificate: row.signing_certificate,
    enabled: row.enabled === 1,
  };
}

/** Registrations are always created disabled until the protocol implementation is ready. */
/** A duplicate insert returns false; any other constraint failure throws. */
export async function createSamlServiceProvider(env: Env, input: Omit<SamlServiceProvider, "enabled">): Promise<boolean> {
  validateSamlServiceProvider({ ...input, enabled: false });
  let changes: number;
  try {
    const result = await env.DB.prepare(
      `INSERT INTO saml_service_providers
       (id, entity_id, acs_url, signing_certificate, enabled) VALUES (?, ?, ?, ?, 0)`,
    ).bind(input.id, input.entityId, input.acsUrl, input.signingCertificate).run();
    changes = result.meta.changes;
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (!message.includes("UNIQUE constraint failed")) throw error;
    changes = 0;
  }
  return changes === 1;
}

/** Set the enabled flag. Returns false when the registration does not exist. */
export async function setSamlServiceProviderEnabled(
  env: Env,
  id: string,
  enabled: boolean,
): Promise<boolean> {
  if (!id || id.length > 128) return false;
  const result = await env.DB.prepare(
    "UPDATE saml_service_providers SET enabled = ? WHERE id = ?",
  ).bind(enabled ? 1 : 0, id).run();
  return result.meta.changes === 1;
}
