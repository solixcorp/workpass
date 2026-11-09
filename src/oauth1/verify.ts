import { parseOAuth1AuthorizationHeader } from "./authorization-header";
import { oauth1HmacSha1, oauth1SignatureBaseString, type OAuth1Parameter } from "./signature";

/** Secrets must be loaded only for an active consumer and, when present, an
 * active token owned by that consumer. The caller decides which token type is
 * appropriate for the endpoint. */
export interface OAuth1Credential {
  consumerSecret: string;
  tokenSecret?: string;
}

export interface OAuth1VerificationOptions {
  resolveCredential(consumerKey: string, token: string | undefined): Promise<OAuth1Credential | null>;
  /** Atomically insert the tuple if absent; return false on replay. Errors must throw. */
  claimNonce(consumerKey: string, token: string | undefined, timestamp: number, nonce: string): Promise<boolean>;
  now?: number; // Unix seconds
  maxClockSkew?: number;
}

export interface OAuth1VerifiedRequest {
  consumerKey: string;
  token: string | undefined;
  parameters: readonly OAuth1Parameter[];
}

/** Verify header-authenticated HMAC-SHA1 requests. OAuth protocol parameters
 * in the query or form body are rejected to prevent ambiguity. Ordinary query
 * and form parameters are included in the signature. This function does not
 * perform user authorization or issue tokens. */
export async function verifyOAuth1Request(request: Request, options: OAuth1VerificationOptions): Promise<OAuth1VerifiedRequest | null> {
  try {
    const header = request.headers.get("Authorization");
    if (!header) return null;
    const oauth = parseOAuth1AuthorizationHeader(header);
    const values = new Map(oauth);
    const consumerKey = values.get("oauth_consumer_key");
    const nonce = values.get("oauth_nonce");
    const timestampString = values.get("oauth_timestamp");
    const signature = values.get("oauth_signature");
    const token = values.get("oauth_token");
    if (!consumerKey || !nonce || !timestampString || !signature || (token !== undefined && !token)) return null;
    if (consumerKey.length > 512 || nonce.length > 512 || (token?.length ?? 0) > 512 || signature.length > 128) return null;
    if (values.get("oauth_signature_method") !== "HMAC-SHA1") return null;
    if (values.has("oauth_version") && values.get("oauth_version") !== "1.0") return null;
    if (!/^[0-9]{1,15}$/.test(timestampString)) return null;
    const timestamp = Number(timestampString);
    const now = options.now ?? Math.floor(Date.now() / 1000);
    const skew = options.maxClockSkew ?? 300;
    if (!Number.isSafeInteger(timestamp) || !Number.isSafeInteger(now) || !Number.isSafeInteger(skew) || skew < 0 || Math.abs(now - timestamp) > skew) return null;

    const url = new URL(request.url);
    let mixedParameters = false;
    url.searchParams.forEach((_value, name) => { if (name.startsWith("oauth_")) mixedParameters = true; });
    if (mixedParameters) return null;
    const body: OAuth1Parameter[] = [];
    const contentType = request.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType === "application/x-www-form-urlencoded") {
      const text = await request.clone().text();
      if (text.length > 65536) return null;
      new URLSearchParams(text).forEach((value, name) => {
        if (name.startsWith("oauth_")) mixedParameters = true;
        body.push([name, value]);
      });
      if (mixedParameters) return null;
    }
    const credential = await options.resolveCredential(consumerKey, token);
    if (!credential || (token !== undefined && credential.tokenSecret === undefined)) return null;
    const base = oauth1SignatureBaseString(request.method, request.url, [...oauth, ...body]);
    const expected = await oauth1HmacSha1(base, credential.consumerSecret, token === undefined ? "" : credential.tokenSecret!);
    // Verify using Web Crypto rather than data-dependent string comparison.
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(expected), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(expected));
    if (!await crypto.subtle.verify("HMAC", key, mac, new TextEncoder().encode(signature))) return null;
    if (!await options.claimNonce(consumerKey, token, timestamp, nonce)) return null;
    return { consumerKey, token, parameters: oauth };
  } catch {
    // A malformed request, credential-store failure, or nonce-store failure is
    // never treated as authentication success.
    return null;
  }
}
