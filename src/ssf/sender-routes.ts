import { Hono } from "hono";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { constantTimeTokenMatches } from "../security/tokens";
import { ensureSsfSigningKey } from "./keys";
import { deleteSsfRecipient, dispatchSSFEvent, ensureSsfDispatchTables, upsertSsfRecipient } from "./dispatch";

/**
 * SSF sender management: operator-gated recipient registration, a public JWKS
 * endpoint for the platform's SET signing key, and explicit event dispatch.
 * Event generation is not wired to user lifecycle changes yet — operators can
 * dispatch test/spec events and event-emitting call sites will be connected
 * after review of the account-lifecycle semantics.
 */

export const ssfSenderRoutes = new Hono<{ Bindings: Env }>();

function enabled(env: Env): boolean {
  return env.ENABLE_SSF_SENDER === "true";
}

function authorized(env: Env, request: Request): boolean {
  const token = (request.headers.get("authorization") ?? "").replace(/^Bearer /, "");
  return Boolean(env.SSF_MANAGEMENT_TOKEN) && constantTimeTokenMatches(token, env.SSF_MANAGEMENT_TOKEN!);
}function audit(env: Env, event: Omit<Parameters<typeof insertAuditEvent>[1], "id">): Promise<void> {
  return insertAuditEvent(env, { id: crypto.randomUUID(), ...event });
}

export async function cleanupSsfDeliveries(env: Env, nowMs: number): Promise<void> {
  await ensureSsfDispatchTables(env.DB);
  if (!Number.isSafeInteger(nowMs)) throw new Error("Invalid cleanup time");
  // Retain a bounded window of terminal rows for inspection; pending rows stay.
  const horizon = nowMs - 30 * 24 * 3600 * 1000;
  await env.DB.prepare("DELETE FROM ssf_deliveries WHERE state IN ('delivered','failed','abandoned') AND updated_at < ?")
    .bind(horizon).run();
}

ssSenderJwksRoute(ssfSenderRoutes);

function ssSenderJwksRoute(router: Hono<{ Bindings: Env }>): void {
  router.get("/api/ssf/jwks.json", async (context) => {
    if (!enabled(context.env)) return context.notFound();
    try {
      const key = await ensureSsfSigningKey(context.env);
      return context.json({ keys: [key.publicJwk] }, 200, { "Cache-Control": "public, max-age=300" });
    } catch (error) {
      if (error instanceof Error && error.message.includes("AEAD_SEALING_KEY")) {
        return context.json({ error: "Sealed storage is not configured" }, 503);
      }
      return context.json({ error: "Signing key unavailable" }, 500);
    }
  });
}

ssfSenderRoutes.post("/api/ssf/streams", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  if (!authorized(context.env, context.req.raw)) return context.json({ error: "Unauthorized" }, 401);
  await ensureSsfDispatchTables(context.env.DB);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const input = body as {
    id?: unknown; audience?: unknown; endpoint?: unknown; event_types?: unknown; delivery_token?: unknown;
  };
  if (typeof input.id !== "string" || !input.id || input.id.length > 128 ||
      typeof input.audience !== "string" || !input.audience ||
      typeof input.endpoint !== "string" || !input.endpoint ||
      !Array.isArray(input.event_types) || input.event_types.some((t) => typeof t !== "string") ||
      (input.delivery_token !== undefined && typeof input.delivery_token !== "string")) {
    return context.json({ error: "id, audience, endpoint, event_types are required" }, 400);
  }
  try {
    await upsertSsfRecipient(context.env, {
      id: input.id, audience: input.audience, endpoint: input.endpoint,
      eventTypes: input.event_types as string[],
      deliveryToken: input.delivery_token as string | undefined,
    });
    await audit(context.env, { actor_user_id: null, target_user_id: null,
      event_type: "ssf.recipient.register", outcome: "success", request_path: "/api/ssf/streams" });
    return context.json({ status: "registered" }, 201);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Recipient endpoint")) {
      return context.json({ error: error.message }, 400);
    }
    return context.json({ error: "Recipient registration failed" }, 500);
  }
});

ssfSenderRoutes.delete("/api/ssf/streams/:id", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  if (!authorized(context.env, context.req.raw)) return context.json({ error: "Unauthorized" }, 401);
  await ensureSsfDispatchTables(context.env.DB);
  const deleted = await deleteSsfRecipient(context.env, context.req.param("id")).catch(() => null);
  if (deleted === null) return context.json({ error: "Recipient delete failed" }, 500);
  if (!deleted) return context.json({ error: "Recipient not found" }, 404);
  await audit(context.env, { actor_user_id: null, target_user_id: null,
    event_type: "ssf.recipient.delete", outcome: "success", request_path: "/api/ssf/streams" });
  return context.json({ status: "deleted" });
});

ssfSenderRoutes.post("/api/ssf/events", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  if (!authorized(context.env, context.req.raw)) return context.json({ error: "Unauthorized" }, 401);
  await ensureSsfDispatchTables(context.env.DB);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const input = body as { recipient_id?: unknown; event_type?: unknown; subject?: unknown; description?: unknown };
  if (typeof input.recipient_id !== "string" || !input.recipient_id ||
      typeof input.event_type !== "string" || !input.event_type ||
      typeof input.subject !== "object" || input.subject === null) {
    return context.json({ error: "recipient_id, event_type, subject are required" }, 400);
  }
  try {
    const result = await dispatchSSFEvent(context.env, {
      recipientId: input.recipient_id, eventType: input.event_type,
      subject: input.subject as Record<string, unknown>,
      description: typeof input.description === "object" && input.description !== null
        ? input.description as Record<string, unknown> : undefined,
    });
    return context.json(result, result.state === "delivered" ? 200 : 202);
  } catch (error) {
    if (error instanceof Error && (error.message === "Recipient not found" || error.message.startsWith("Event type"))) {
      return context.json({ error: error.message }, 404);
    }
    return context.json({ error: "Event dispatch failed" }, 500);
  }
});
