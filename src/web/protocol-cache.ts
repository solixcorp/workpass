/**
 * Short-TTL edge caching for immutable-leaning protocol documents (OIDC
 * discovery, SAML metadata): identical bytes served repeatedly, invalidated
 * explicitly when the underlying key material changes (SAML key rotation).
 *
 * The Cache API is a pass-through no-op where it is not available (e.g.
 * workers.dev subdomains without a zone), so this must never break requests;
 * every cache interaction is best-effort inside try/catch.
 */

const DOCUMENT_TTL_SECONDS = 60;

function cacheKeyFor(url: URL): Request {
  // The cache key is the exact request URL; requests may vary by nothing else.
  return new Request(url.toString());
}

/** Respond from the edge cache when a fresh document exists; null otherwise. */
export async function cachedProtocolDocument(url: URL): Promise<Response | null> {
  try {
    const cache = (caches as unknown as { default: Cache }).default;
    const stored = await cache.match(cacheKeyFor(url));
    if (!stored) return null;
    // Re-assert the protocol no-store policy for the downstream client copy:
    // the edge may serve the cached document, but the client must not keep it.
    const body = await stored.text();
    const headers = new Headers(stored.headers);
    headers.set("Cache-Control", "public, max-age=60");
    return new Response(body, { status: stored.status, headers });
  } catch {
    return null;
  }
}

/** Store a protocol document in the edge cache (best-effort). */
export async function storeProtocolDocument(url: URL, response: Response, ttlSeconds = DOCUMENT_TTL_SECONDS): Promise<void> {
  try {
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", `public, max-age=${ttlSeconds}`);
    const stored = new Response(await response.clone().text(), {
      status: response.status,
      headers,
    });
    const cache = (caches as unknown as { default: Cache }).default;
    await cache.put(cacheKeyFor(url), stored);
  } catch {
    // Caching is unavailable in some contexts; treat as a pass-through.
  }
}

/** Invalidate a cached protocol document (best-effort). */
export async function invalidateProtocolDocument(url: URL): Promise<void> {
  try {
    const cache = (caches as unknown as { default: Cache }).default;
    await cache.delete(cacheKeyFor(url));
  } catch {
    // Best-effort invalidation.
  }
}
