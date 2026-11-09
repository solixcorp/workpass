import type { Env } from "../env";

/** Registration data only. This does not enable a SAML protocol endpoint. */
export interface SamlServiceProvider {
  id: string;
  entityId: string;
  acsUrl: string;
  signingCertificate: string;
  enabled: boolean;
}

export function validateSamlServiceProvider(input: SamlServiceProvider): void {
  if (!input.id || input.id.length > 128 || !input.entityId || input.entityId.length > 2048) {
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
