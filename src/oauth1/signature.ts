/** RFC 5849 signature base string and HMAC-SHA1 primitives.
 * This module alone does not implement an OAuth 1.0 authorization server.
 */
export type OAuth1Parameter = readonly [string, string];

export function oauthPercentEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

export function oauth1SignatureBaseString(
  method: string,
  requestUrl: string,
  parameters: readonly OAuth1Parameter[],
): string {
  const url = new URL(requestUrl);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Invalid OAuth URL");
  const baseUrl = `${url.protocol}//${url.host}${url.pathname || "/"}`;
  const pairs: [string, string][] = [];
  url.searchParams.forEach((value, name) => pairs.push([name, value]));
  for (const [name, value] of parameters) pairs.push([name, value]);
  // Callers must omit the OAuth Authorization header's realm parameter; a
  // query or form parameter named realm is an ordinary signed parameter.
  const encoded = pairs.filter(([name]) => name !== "oauth_signature")
    .map(([name, value]) => [oauthPercentEncode(name), oauthPercentEncode(value)] as const)
    .sort(([a, av], [b, bv]) => a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0)
    .map(([name, value]) => `${name}=${value}`).join("&");
  return `${oauthPercentEncode(method.toUpperCase())}&${oauthPercentEncode(baseUrl)}&${oauthPercentEncode(encoded)}`;
}

export async function oauth1HmacSha1(
  baseString: string,
  clientSecret: string,
  tokenSecret = "",
): Promise<string> {
  const signingKey = `${oauthPercentEncode(clientSecret)}&${oauthPercentEncode(tokenSecret)}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(signingKey), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(baseString)));
  return btoa(String.fromCharCode(...signature));
}
