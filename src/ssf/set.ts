// OpenID SSF 1.0 / RFC 8417. Keys and stream configuration must come from
// trusted configuration, never from unverified JWT header URLs.
export type SetClaims = {
  iss: string; jti: string; iat: number; aud: string | string[];
  sub_id: Record<string, unknown>; events: Record<string, Record<string, unknown>>;
  [key: string]: unknown;
};

export type SetAlgorithm = 'RS256' | 'ES256';

export type StreamTrust = {
  issuer: string;
  audience: string;
  eventTypes: readonly string[];
  keys: ReadonlyMap<string, CryptoKey>;
  maxAgeSeconds: number;
  clockSkewSeconds?: number;
  algorithms?: readonly SetAlgorithm[];
  criticalSubjectMembers?: readonly string[];
  understoodSubjectMembers?: readonly string[];
};

export class SetError extends Error {
  constructor(readonly code: 'invalid_request' | 'invalid_key' | 'invalid_issuer' | 'invalid_audience', message: string) { super(message); }
}

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = (value: unknown): value is string => typeof value === 'string' && value.length > 0;
const validRsa = (key: CryptoKey) => {
  const alg = key.algorithm as KeyAlgorithm & { hash?: { name: string }; modulusLength?: number };
  return alg.name === 'RSASSA-PKCS1-v1_5' && alg.hash?.name === 'SHA-256' && (alg.modulusLength ?? 0) >= 2048;
};
const validEs256 = (key: CryptoKey) => {
  const alg = key.algorithm as KeyAlgorithm & { namedCurve?: string };
  return alg.name === 'ECDSA' && alg.namedCurve === 'P-256';
};
const verificationAlgorithm = (algorithm: SetAlgorithm) =>
  algorithm === 'RS256' ? 'RSASSA-PKCS1-v1_5' as AlgorithmIdentifier : ({ name: 'ECDSA', hash: 'SHA-256' } as AlgorithmIdentifier);

function decode(part: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new SetError('invalid_request', 'Invalid encoding');
  try {
    const text = atob(part.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - part.length % 4) % 4));
    return Uint8Array.from(text, c => c.charCodeAt(0));
  } catch { throw new SetError('invalid_request', 'Invalid encoding'); }
}

function json(part: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(part)));
    if (object(value)) return value;
  } catch { /* invalid JSON */ }
  throw new SetError('invalid_request', 'Invalid JSON');
}

export async function verifySet(token: string, trust: StreamTrust, now = Math.floor(Date.now() / 1000)): Promise<SetClaims> {
  if (!Number.isFinite(trust.maxAgeSeconds) || trust.maxAgeSeconds <= 0 || !nonempty(trust.issuer) || !nonempty(trust.audience)) throw new Error('Invalid stream trust');
  const skew = trust.clockSkewSeconds ?? 60;
  if (!Number.isFinite(skew) || skew < 0 || skew > 300) throw new Error('Invalid clock skew');
  if (token.length > 65536) throw new SetError('invalid_request', 'SET too large');
  const parts = token.split('.');
  if (parts.length !== 3) throw new SetError('invalid_request', 'Invalid SET');
  const header = json(parts[0]);
  const algorithms = trust.algorithms ?? (['RS256'] as const);
  const keyValid = (key: CryptoKey, algorithm: SetAlgorithm) =>
    algorithm === 'RS256' ? validRsa(key) : validEs256(key);
  if (header.typ !== 'secevent+jwt' || !algorithms.includes(header.alg as SetAlgorithm) || !nonempty(header.kid) || 'crit' in header || 'b64' in header) throw new SetError('invalid_request', 'Invalid SET header');
  const key = trust.keys.get(header.kid);
  if (!key || key.type !== 'public' || !keyValid(key, header.alg as SetAlgorithm)) throw new SetError('invalid_key', 'Untrusted signing key');
  let verified = false;
  try { verified = await crypto.subtle.verify(verificationAlgorithm(header.alg as SetAlgorithm), key, decode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`)); } catch { /* invalid signature */ }
  if (!verified) throw new SetError('invalid_key', 'Invalid signature');
  const c = json(parts[1]);
  if (c.iss !== trust.issuer) throw new SetError('invalid_issuer', 'Invalid issuer');
  const aud = typeof c.aud === 'string' ? [c.aud] : c.aud;
  if (!Array.isArray(aud) || !aud.length || !aud.every(nonempty) || !aud.includes(trust.audience)) throw new SetError('invalid_audience', 'Invalid audience');
  if (!nonempty(c.jti) || typeof c.iat !== 'number' || !Number.isFinite(c.iat) || c.iat > now + skew || c.iat < now - trust.maxAgeSeconds - skew || 'exp' in c || 'sub' in c || ('nbf' in c && (typeof c.nbf !== 'number' || !Number.isFinite(c.nbf) || c.nbf > now + skew))) throw new SetError('invalid_request', 'Invalid SET claims');
  if (!object(c.sub_id) || !nonempty(c.sub_id.format)) throw new SetError('invalid_request', 'Invalid subject');
  if (c.sub_id.format === 'complex') {
    const members = Object.entries(c.sub_id).filter(([name]) => name !== 'format');
    if (!members.length || members.some(([, v]) => !object(v) || !nonempty(v.format) || v.format === 'complex')) throw new SetError('invalid_request', 'Invalid complex subject');
    if (members.some(([name]) => trust.criticalSubjectMembers?.includes(name) && !trust.understoodSubjectMembers?.includes(name))) throw new SetError('invalid_request', 'Unsupported critical subject');
  }
  if (!object(c.events) || Object.keys(c.events).length !== 1 || Object.entries(c.events).some(([type, event]) => !trust.eventTypes.includes(type) || !object(event))) throw new SetError('invalid_request', 'Unsupported event');
  return c as SetClaims;
}

export async function signSet(claims: SetClaims, kid: string, key: CryptoKey): Promise<string> {
  if (!nonempty(kid) || key.type !== 'private' || !validRsa(key)) throw new Error('Invalid signing key');
  const encode = (value: Uint8Array) => btoa(Array.from(value, byte => String.fromCharCode(byte)).join('')).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const encodeJson = (value: unknown) => encode(new TextEncoder().encode(JSON.stringify(value)));
  const input = `${encodeJson({ typ: 'secevent+jwt', alg: 'RS256', kid })}.${encodeJson(claims)}`;
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(input));
  return `${input}.${encode(new Uint8Array(signature))}`;
}
