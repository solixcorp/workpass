import { Hono } from "hono";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { constantTimeTokenMatches } from "../security/tokens";
import { createSsfInbox, ensureSsfInboxTable } from "./inbox";
import { receivePush } from "./push";
import type { SetAlgorithm } from "./set";
import { deliveryTokenMatches, parseSsfStreams, streamById } from "./streams";

/**
 * SSF shared-signal receiver: POST /api/ssf/receiver/:streamId accepts
 * application/secevent+jwt SETs for operator-configured streams. The receiver
 * validates the signature against pinned keys, atomically queues the event,
 * and replies 202. Authentication is per-stream shared secret (delivery_token).
 */

export const ssfReceiverRoutes = new Hono<{ Bindings: Env }>();

function enabled(env: Env): boolean {
  return env.ENABLE_SSF_RECEIVER === "true";
}

/** Trusted keys imported per request; keyed by `kid` from the JWT header. */
async function buildTrust(env: Env, streamId: string) {
  const stream = streamById(env, streamId);
  if (!stream) return null;
  const keys = new Map<string, CryptoKey>();
  for (const jwk of stream.jwks.keys) {
    if (typeof jwk.kid !== "string" || !jwk.kid || jwk.kty !== "RSA") continue;
    try {
      keys.set(jwk.kid, await crypto.subtle.importKey(
        "jwk", jwk as JsonWebKey,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
      ));
    } catch { /* unimportable key: skip, remaining keys may still verify */ }
  }
  if (keys.size === 0) return null;
  return { stream, keys };
}

function algorithmsFor(env: Env): readonly SetAlgorithm[] {
  return ["RS256"];
}

function audit(env: Env, event: Omit<Parameters<typeof insertAuditEvent>[1], "id">): Promise<void> {
  return insertAuditEvent(env, { id: crypto.randomUUID(), ...event });
}

async function failClosedAudit(env: Env): Promise<boolean> {
  try {
    await audit(env, { actor_user_id: null, target_user_id: null,
      event_type: "ssf.receiver.event", outcome: "success", request_path: "/api/ssf/receiver" });
    return true;
  } catch {
    // The event is already durably queued; the audit gap is surfaced for
    // reconciliation rather than falsely reporting delivery failure.
    return false;
  }
}

ssfReceiverRoutes.post("/api/ssf/receiver/:streamId", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  await ensureSsfInboxTable(context.env.DB);
  const trust = await buildTrust(context.env, context.req.param("streamId"));
  if (!trust) return context.json({ err: "unknown_stream" }, 404);
  const provided = (context.req.header("authorization") ?? "").replace(/^Bearer /, "");
  if (!deliveryTokenMatches(context.env, trust.stream, provided)) {
    return context.json({ err: "unauthorized_stream" }, 401);
  }
  const inbox = createSsfInbox(context.env.DB);
  const response = await receivePush(context.req.raw, trust.stream.id, {
    issuer: trust.stream.issuer, audience: trust.stream.audience,
    keys: trust.keys, eventTypes: trust.stream.event_types,
    maxAgeSeconds: trust.stream.max_age_seconds ?? 3600,
    algorithms: algorithmsFor(context.env),
  }, inbox);
  if (response.status === 202) {
    // Queue + audit are independent; receiving must never mutate accounts
    // until a dedicated, event-specific handler processes the row.
    const audited = await failClosedAudit(context.env);
    if (!audited) return context.json({ err: "processing_backlog" }, 503);
  }
  return response;
});

/** Operator introspection: the streams this receiver knows about. */
ssfReceiverRoutes.get("/api/ssf/streams", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  const token = (context.req.header("authorization") ?? "").replace(/^Bearer /, "");
  if (!context.env.SSF_MANAGEMENT_TOKEN || !constantTimeTokenMatches(token, context.env.SSF_MANAGEMENT_TOKEN)) {
    return context.json({ error: "Unauthorized" }, 401);
  }
  try {
    return context.json({ streams: parseSsfStreams(context.env.SSF_STREAMS).map((stream) => ({
      id: stream.id, issuer: stream.issuer, audience: stream.audience,
      event_types: stream.event_types, requires_delivery_token: Boolean(stream.delivery_token),
    })) });
  } catch {
    return context.json({ error: "SSF_STREAMS is not configured" }, 503);
  }
});
