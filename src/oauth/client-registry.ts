/**
 * Direct oauthClient row access for the grant routers (device authorization,
 * CIBA backchannel). The provider's own endpoints own the oauthClient table;
 * these reads mirror its storage conventions: array columns are JSON strings,
 * client secrets are stored hashed (SHA-256, base64url, no padding — the
 * provider's defaultHasher), and rows carry their registration state.
 */

import type { Env } from "../env";

export interface RegisteredClient {
  clientId: string;
  name: string;
  disabled: boolean;
  scopes: string[] | null;
  grantTypes: string[] | null;
  tokenEndpointAuthMethod: string | null;
  clientSecretHash: string | null;
}

export function clientAllowsGrant(grantTypes: string[] | null, grantType: string): boolean {
  const allowed = grantTypes && grantTypes.length > 0 ? grantTypes : ["authorization_code"];
  return allowed.includes(grantType);
}

function parseArray(value: unknown): string[] | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every((entry) => typeof entry === "string")
      ? (parsed as string[])
      : null;
  } catch {
    return null;
  }
}

export async function loadRegisteredClient(env: Env, clientId: string): Promise<RegisteredClient | null> {
  const raw = await env.DB.prepare(
    `SELECT clientId, name, disabled, scopes, grantTypes, tokenEndpointAuthMethod, clientSecret
     FROM oauthClient WHERE clientId = ? LIMIT 1`,
  ).bind(clientId).first<{
    clientId: string;
    name: string | null;
    disabled: number | null;
    scopes: unknown;
    grantTypes: unknown;
    tokenEndpointAuthMethod: string | null;
    clientSecret: string | null;
  }>();
  if (!raw) return null;
  return {
    clientId: raw.clientId,
    name: raw.name ?? raw.clientId,
    disabled: raw.disabled === 1,
    scopes: parseArray(raw.scopes),
    grantTypes: parseArray(raw.grantTypes),
    tokenEndpointAuthMethod: raw.tokenEndpointAuthMethod,
    clientSecretHash: raw.clientSecret,
  };
}

/**
 * Server-side client-secret verification over the provider's stored hash
 * (SHA-256 → base64url unpadded). Only meaningful for hashed-secret storage —
 * the deployment default (storeClientSecret defaults to "hashed" while the JWT
 * plugin is enabled).
 */
export async function matchesStoredClientSecret(presented: string, stored: string | null): Promise<boolean> {
  if (!stored) return false;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(presented));
  const encoded = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return encoded === stored;
}
