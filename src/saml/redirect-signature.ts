/** HTTP-Redirect binding signature verification for an already trusted SP key. */
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

export interface VerifiedRedirectBinding {
  samlRequest: string;
  relayState: string | null;
}

/**
 * Verify the exact URL-encoded octets received from the browser. The trusted
 * public key must come from the registered SP, never from the request itself.
 * This only validates the binding signature, not the decompressed XML or user.
 */
export async function verifySamlRedirectSignature(
  requestUrl: string,
  trustedKey: CryptoKey,
): Promise<VerifiedRedirectBinding | null> {
  const url = new URL(requestUrl);
  const pieces = url.search.slice(1).split("&");
  const entries = new Map<string, { raw: string; value: string }>();
  for (const piece of pieces) {
    if (!piece) continue;
    const separator = piece.indexOf("=");
    if (separator < 0) return null;
    const rawName = piece.slice(0, separator);
    const rawValue = piece.slice(separator + 1);
    let name: string;
    let value: string;
    try {
      name = decodeURIComponent(rawName.replace(/\+/g, " "));
      value = decodeURIComponent(rawValue.replace(/\+/g, " "));
    } catch {
      return null;
    }
    if (["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"].includes(name)) {
      if (rawName !== name || entries.has(name)) return null;
      entries.set(name, { raw: rawValue, value });
    }
  }
  const message = entries.get("SAMLRequest");
  const algorithm = entries.get("SigAlg");
  const signature = entries.get("Signature");
  const relay = entries.get("RelayState");
  if (
    !message?.value || message.value.length > 32_768 || entries.has("SAMLResponse") ||
    algorithm?.value !== RSA_SHA256 || !signature?.value || signature.value.length > 2048 ||
    (relay && new TextEncoder().encode(relay.value).length > 80) ||
    trustedKey.type !== "public" || trustedKey.algorithm.name !== "RSASSA-PKCS1-v1_5" ||
    !trustedKey.usages.includes("verify")
  ) return null;
  const signed = `SAMLRequest=${message.raw}${relay ? `&RelayState=${relay.raw}` : ""}&SigAlg=${algorithm.raw}`;
  try {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signature.value)) return null;
    const padded = signature.value.padEnd(Math.ceil(signature.value.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5", trustedKey, bytes, new TextEncoder().encode(signed),
    );
    return ok ? { samlRequest: message.value, relayState: relay?.value ?? null } : null;
  } catch {
    return null;
  }
}
