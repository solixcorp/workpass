import { describe, expect, test } from 'bun:test';
import { signSet, verifySet, type SetClaims, type StreamTrust } from '../src/ssf/set';
import { deliverPush, receivePush } from '../src/ssf/push';

describe('SSF push', () => {
  test('verifies, persists atomically before acknowledging, and accepts duplicates', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
    const event = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';
    const claims: SetClaims = { iss: 'https://issuer.example', aud: 'receiver', jti: 'id', iat: Math.floor(Date.now() / 1000), sub_id: { format: 'email', email: 'user@example.com' }, events: { [event]: {} } };
    const trust: StreamTrust = { issuer: claims.iss, audience: 'receiver', keys: new Map([['key', pair.publicKey]]), eventTypes: [event], maxAgeSeconds: 3600 };
    const token = await signSet(claims, 'key', pair.privateKey);
    expect((await verifySet(token, trust)).jti).toBe('id');
    await expect(verifySet(token, { ...trust, audience: 'other' })).rejects.toThrow();
    await expect(verifySet(await signSet({ ...claims, exp: claims.iat + 10 }, 'key', pair.privateKey), trust)).rejects.toThrow();
    await expect(verifySet(token, trust, claims.iat + 4000)).rejects.toThrow();
    let inserts = 0;
    const seen = new Set<string>();
    const inbox = { async persist(_stream: string, value: SetClaims) { if (seen.has(value.jti)) return 'duplicate' as const; seen.add(value.jti); inserts++; return 'inserted' as const; } };
    const request = () => new Request('https://receiver.example', { method: 'POST', headers: { 'Content-Type': 'application/secevent+jwt' }, body: token });
    expect((await receivePush(request(), 'stream', trust, inbox)).status).toBe(202);
    expect((await receivePush(request(), 'stream', trust, inbox)).status).toBe(202);
    expect(inserts).toBe(1);
    expect((await receivePush(request(), 'stream', trust, { async persist() { throw Error('offline'); } })).status).toBe(503);
    const tampered = token.slice(0, -10) + 'AAAAAAAAAA';
    expect((await receivePush(new Request('https://receiver.example', { method: 'POST', headers: { 'Content-Type': 'application/secevent+jwt' }, body: tampered }), 'stream', trust, inbox)).status).toBe(400);
  });

  test('classifies failures without following redirects', async () => {
    const send = (async (_url: unknown, init?: RequestInit) => { expect(init?.redirect).toBe('error'); return new Response(null, { status: 429, headers: { 'Retry-After': '42' } }); }) as typeof fetch;
    expect(await deliverPush('https://receiver.example/events', 'jwt', undefined, send)).toEqual({ kind: 'retry', status: 429, retryAfterSeconds: 42 });
    await expect(deliverPush('http://receiver.example', 'jwt', undefined, send)).rejects.toThrow();
  });
});
