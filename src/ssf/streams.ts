import { constantTimeTokenMatches } from "../security/tokens";
import type { Env } from "../env";

/**
 * Trusted SSF receiver-stream configuration. Streams come from the operator
 * environment (SSF_STREAMS, a JSON array); keys are pinned in configuration —
 * never fetched from an unverified URL at request time. Each stream may also
 * require a shared delivery token so an unauthenticated party cannot force
 * signature verification work (DoS surface).
 */

export interface SsfStreamConfig {
  id: string;
  issuer: string;
  audience: string;
  jwks: { keys: Record<string, unknown>[] };
  event_types: string[];
  max_age_seconds?: number;
  delivery_token?: string;
}

export function parseSsfStreams(raw: string | undefined): SsfStreamConfig[] {
  if (raw === undefined || raw.trim() === "") return [];
  if (raw.length > 65536) throw new Error("SSF_STREAMS must be at most 65536 characters");
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("SSF_STREAMS must be valid JSON"); }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 50) {
    throw new Error("SSF_STREAMS must be a non-empty JSON array");
  }
  return parsed.map((entry) => {
    const stream = entry as Partial<SsfStreamConfig>;
    if (typeof stream.id !== "string" || !stream.id || typeof stream.issuer !== "string" || !stream.issuer ||
        typeof stream.audience !== "string" || !stream.audience ||
        !Array.isArray(stream.jwks?.keys) || !Array.isArray(stream.event_types) || stream.event_types.length === 0) {
      throw new Error("SSF_STREAMS entries require id, issuer, audience, jwks.keys, event_types");
    }
    return stream as SsfStreamConfig;
  });
}

export function streamById(env: Env, streamId: string): SsfStreamConfig | null {
  try {
    return parseSsfStreams(env.SSF_STREAMS).find((stream) => stream.id === streamId) ?? null;
  } catch (error) {
    console.error("Invalid SSF_STREAMS configuration", {
      name: error instanceof Error ? error.name : "UnknownError",
    });
    return null;
  }
}

export function deliveryTokenMatches(env: Env, stream: SsfStreamConfig, provided: string): boolean {
  if (!stream.delivery_token) return true;
  return constantTimeTokenMatches(provided, stream.delivery_token);
}
