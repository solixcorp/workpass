/**
 * Runtime-independent OIDC crypto helpers for the headless smoke: PKCE S256
 * pairs and ES256 verification of a compact JWT against a published JWKS.
 */

export interface PKCEPair {
  verifier: string;
  challenge: string;
}

export function generatePKCEPair(): Promise<PKCEPair> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const verifier = toBase64Url(raw);
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)).then((bytes) => ({
    verifier,
    challenge: toBase64Url(new Uint8Array(bytes)),
  }));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-|--/g, "+").replace(/_/g, "/");
  const fixed = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(fixed), (char) => char.charCodeAt(0));
}

export interface VerifiedIdToken {
  iss: string;
  aud: string;
  sub: string;
  nonce?: string;
  state?: string;
}

/** Verify a compact ES256 JWT against a JWKS key set (kid matching). */
export async function jwtVerify(token: string, keys: Array<{ kty?: string; x?: string; y?: string; kid?: string }>): Promise<VerifiedIdToken | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const header = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0]!))) as { kid?: string; alg?: string };
  const jwk = keys.find((key) => (!header.kid ? true : key.kid === header.kid));
  if (!jwk || jwk.kty !== "EC" || !jwk.x || !jwk.y) return null;
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: false }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    key,
    fromBase64Url(parts[2]!),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) return null;
  const claims = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1]!))) as VerifiedIdToken;
  return claims;
}

