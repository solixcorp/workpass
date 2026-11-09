import { SetError, verifySet, type SetClaims, type StreamTrust } from './set';

// persist must atomically insert the received SET and its processing job, keyed
// by (streamId, issuer, jti), and leave an existing record unchanged.
export interface Inbox {
  persist(streamId: string, claims: SetClaims, token: string): Promise<'inserted' | 'duplicate'>;
}

export async function receivePush(request: Request, streamId: string, trust: StreamTrust, inbox: Inbox): Promise<Response> {
  if (request.method !== 'POST') return new Response(null, { status: 405, headers: { Allow: 'POST' } });
  if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/secevent+jwt') return new Response(null, { status: 415 });
  // The caller MUST authenticate and authorize the sender for streamId before calling.
  try {
    const length = request.headers.get('content-length');
    if (length && (!/^\d+$/.test(length) || Number(length) > 65536)) return new Response(null, { status: 413 });
    if (!request.body) throw new SetError('invalid_request', 'Missing body');
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 65536) { await reader.cancel(); return new Response(null, { status: 413 }); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    let token: string;
    try { token = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new SetError('invalid_request', 'Invalid encoding'); }
    const claims = await verifySet(token, trust);
    await inbox.persist(streamId, claims, token);
    return new Response(null, { status: 202 });
  } catch (error) {
    if (!(error instanceof SetError)) return new Response(null, { status: 503 });
    return Response.json({ err: error.code, description: error.message }, { status: 400, headers: { 'Content-Language': 'en' } });
  }
}

export type DeliveryResult = { kind: 'delivered' | 'retry' | 'failed'; status?: number; retryAfterSeconds?: number };

// endpoint must be an administratively approved public HTTPS URL; deployments
// must enforce egress/DNS restrictions to prevent SSRF and DNS rebinding.
export async function deliverPush(endpoint: string, token: string, authorization: string | undefined, send: typeof fetch = fetch): Promise<DeliveryResult> {
  const url = new URL(endpoint);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('Invalid delivery endpoint');
  const headers = new Headers({ 'Content-Type': 'application/secevent+jwt', Accept: 'application/json' });
  if (authorization) headers.set('Authorization', authorization);
  let response: Response;
  try { response = await send(url.toString(), { method: 'POST', headers, body: token, redirect: 'error', signal: AbortSignal.timeout(10000) }); }
  catch { return { kind: 'retry' }; }
  if (response.status === 202) return { kind: 'delivered', status: 202 };
  if (response.status === 429 || response.status >= 500 || response.status === 408) {
    const retryAfter = response.headers.get('retry-after');
    const seconds = retryAfter && /^\d+$/.test(retryAfter) ? Math.min(Number(retryAfter), 86400) : undefined;
    return { kind: 'retry', status: response.status, retryAfterSeconds: seconds };
  }
  return { kind: 'failed', status: response.status };
}
