import { Hono } from "hono";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import { requireAdministrator } from "../security/authorization";
import { createScimUser, patchScimUser } from "./client";
import { getScimUserMapping } from "./mappings";
import { claimScimOperation, completeScimCreate, createScimOperation, finishScimOperation, getScimOperation, type ScimOperationType } from "./operations";

export const scimAdminRoutes = new Hono<{ Bindings: Env }>();

/** Read-only reconciliation visibility; no downstream mutation is exposed yet. */
scimAdminRoutes.get("/scim-operations/:id", async (context) => {
  context.header("Cache-Control", "no-store");
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  const operation = await getScimOperation(context.env, context.req.param("id"));
  if (!operation) return context.json({ error: "SCIM operation not found" }, 404);
  return context.json({ operation });
});

scimAdminRoutes.post("/scim-operations", async (context) => {
  context.header("Cache-Control", "no-store");
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;

  const { SCIM_TARGET_ID: targetId, SCIM_BASE_URL: baseUrl, SCIM_BEARER_TOKEN: bearerToken } = context.env;
  if (context.env.ENABLE_SCIM_PROVISIONING !== "true" || !targetId || !baseUrl || !bearerToken) {
    return context.json({ error: "SCIM provisioning is disabled or not configured" }, 503);
  }
  // Development-only loopback allowance: http://127.0.0.1|localhost targets are
  // accepted solely so the transport can be verified against a local mock.
  const allowLoopbackHttp = context.env.SCIM_DEV_LOOPBACK_TARGET === "true";
  try {
    const url = new URL(baseUrl);
    const protocolOk = url.protocol === "https:" ||
      (allowLoopbackHttp && url.protocol === "http:" &&
        (url.hostname === "127.0.0.1" || url.hostname === "localhost"));
    if (!protocolOk || url.username || url.password || url.search || url.hash ||
        !bearerToken.trim() || !/^[A-Za-z0-9_-]{1,128}$/.test(targetId)) {
      return context.json({ error: "SCIM target configuration is invalid" }, 503);
    }
  } catch {
    return context.json({ error: "SCIM target configuration is invalid" }, 503);
  }
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid request" }, 400);
  const input = body as Record<string, unknown>;
  if (typeof input.userId !== "string" || !input.userId || input.userId.length > 256 ||
      (input.operation !== "create" && input.operation !== "update" && input.operation !== "deactivate")) {
    return context.json({ error: "userId and valid operation are required" }, 400);
  }
  const userId = input.userId;
  const operation: ScimOperationType = input.operation;
  return auditStandaloneOperation(context.env, `scim.user.${operation}`, "/api/admin/scim-operations", async () => {
    const user = await context.env.DB.prepare(
      'SELECT id, email, name, username, banned FROM "user" WHERE id = ?',
    ).bind(userId).first<{ id: string; email: string; name: string; username: string | null; banned: number | null }>();
    if (!user) return { response: Response.json({ error: "User not found" }, { status: 404 }), actorUserId: adminSession.userId, targetUserId: userId };
    if (operation === "create" && user.banned) {
      return { response: Response.json({ error: "Disabled users cannot be provisioned" }, { status: 409 }), actorUserId: adminSession.userId, targetUserId: userId };
    }
    const opId = await createScimOperation(context.env, { targetId, userId, operation });
    if (!opId) return { response: Response.json({ error: "SCIM operation requires reconciliation" }, { status: 409 }), actorUserId: adminSession.userId, targetUserId: userId };
    if (!await claimScimOperation(context.env, opId)) throw new Error("SCIM operation claim failed");
    let remoteAttempted = false;
    try {
      const mapped = await getScimUserMapping(context.env, targetId, userId);
      if ((operation === "create" && mapped) || (operation !== "create" && !mapped)) {
        await finishScimOperation(context.env, opId, "failed");
        return { response: Response.json({ error: "SCIM mapping conflict", operationId: opId }, { status: 409 }), actorUserId: adminSession.userId, targetUserId: userId };
      }
      const target = { baseUrl, bearerToken, allowLoopbackHttp };
      remoteAttempted = true;
      const result = operation === "create"
        ? await createScimUser(target, { externalId: user.id, userName: user.username || user.email, displayName: user.name, email: user.email, active: true })
        : await patchScimUser(target, mapped!, operation === "deactivate"
          ? { active: false }
          : { userName: user.username || user.email, displayName: user.name, email: user.email });
      if (!result.ok) {
        const unknown = result.kind === "outcome_unknown" || result.kind === "invalid_response";
        await finishScimOperation(context.env, opId, unknown ? "outcome_unknown" : "failed", result.status ?? null);
        return { response: Response.json({ error: unknown ? "SCIM outcome requires reconciliation" : "SCIM operation failed", operationId: opId }, { status: 502 }), actorUserId: adminSession.userId, targetUserId: userId };
      }
      if (operation === "create") {
        const created = result.value as { id: string };
        if (!await completeScimCreate(context.env, opId, targetId, userId, created.id)) {
          await finishScimOperation(context.env, opId, "outcome_unknown", 201);
          return { response: Response.json({ error: "SCIM mapping requires reconciliation", operationId: opId }, { status: 503 }), actorUserId: adminSession.userId, targetUserId: userId };
        }
      } else if (!await finishScimOperation(context.env, opId, "succeeded")) {
        throw new Error("SCIM completion failed");
      }
      return { response: Response.json({ operationId: opId, status: "succeeded" }), actorUserId: adminSession.userId, targetUserId: userId };
    } catch {
      try { await finishScimOperation(context.env, opId, remoteAttempted ? "outcome_unknown" : "failed"); } catch { /* in-progress stays locked for reconciliation */ }
      return { response: Response.json({ error: "SCIM operation requires reconciliation", operationId: opId }, { status: 503 }), actorUserId: adminSession.userId, targetUserId: userId };
    }
  });
});
