/** Authorization checks shared by the RFC 8693 grant implementation.
 * Deliberately limited to exchanging an access token for the same client
 * and a narrower scope than the subject token. Audience changes are allowed
 * (RFC 8693 §4 audience restriction) but the caller must separately enforce
 * an explicit per-client target allowlist; the lifetime rule keeps every
 * issued token strictly inside the subject token's remaining lifetime, which
 * requires the target resource's configured TTL to be short enough. */
export const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface ExchangeAuthorizationInput {
  clientId: string;
  subject: {
    active: boolean;
    clientId?: unknown;
    userId?: unknown;
    expiresAt?: unknown;
    scopes?: unknown;
    confirmation?: unknown;
  };
  resource: string;
  requestedScopes?: string;
  /** Longest possible lifetime of a new token, in seconds. */
  outputLifetimeSeconds: number;
  nowSeconds: number;
}

export function authorizeExchange(input: ExchangeAuthorizationInput): { userId: string; scopes: string[] } | null {
  const subject = input.subject;
  if (!subject.active || subject.clientId !== input.clientId || typeof subject.userId !== "string" || !subject.userId) return null;
  // Do not silently strip proof-of-possession restrictions from bound tokens.
  if (subject.confirmation != null) return null;
  if (!Number.isInteger(input.outputLifetimeSeconds) || input.outputLifetimeSeconds <= 0 ||
      !Number.isFinite(input.nowSeconds) || typeof subject.expiresAt !== "number" ||
      !Number.isFinite(subject.expiresAt) || subject.expiresAt < input.nowSeconds + input.outputLifetimeSeconds) return null;
  if (typeof input.resource !== "string" || input.resource.length > 2048) return null;
  try {
    const resource = new URL(input.resource);
    if (resource.protocol !== "https:" || resource.username || resource.password || resource.hash) return null;
  } catch { return null; }
  if (typeof subject.scopes !== "string") return null;
  const validScope = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
  const parse = (value: string): string[] | null => {
    if (!value || value.length > 2048) return null;
    const scopes = value.split(" ");
    if (scopes.some((s) => !validScope.test(s)) || new Set(scopes).size !== scopes.length) return null;
    return scopes;
  };
  const granted = parse(subject.scopes);
  const requested = input.requestedScopes === undefined ? granted : parse(input.requestedScopes);
  if (!granted || !requested || requested.some((scope) => !granted.includes(scope))) return null;
  // Exchanging must not mint an ID token or refresh token through the provider.
  if (requested.includes("openid") || requested.includes("offline_access")) return null;
  return { userId: subject.userId, scopes: requested };
}
