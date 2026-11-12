/**
 * RFC 8628 Device Authorization Grant — authorization endpoint, human approval
 * surface, and the verification page. Routes fail closed behind
 * ENABLE_DEVICE_FLOW. The device hits POST /oauth2/device/authorize (public,
 * client_id + scope); the human opens /device (the single-page app), signs in if needed, types
 * the user code, and approves or denies. Approval binds the grant to the
 * approving user and session; the token grant (src/oauth/extended-grants.ts)
 * consumes it exactly once.
 */

import { Hono, type Context } from "hono";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { createAuth } from "../auth/config";
import { checkOidcAccess } from "../access/oidc-gate";
import {
  createDeviceGrant, decideDeviceGrant, loadDeviceGrantByUserCode, normalizeUserCode,
} from "./device-flow";
import { clientAllowsGrant, loadRegisteredClient } from "./client-registry";

type FormBody = Record<string, string | File>;

/** The device posts a form; the approval page posts JSON. */
async function formBody(context: Context<{ Bindings: Env }>): Promise<FormBody> {
  if ((context.req.header("content-type") ?? "").includes("application/json")) {
    const body = await context.req.json().catch(() => ({})) as unknown;
    return (body && typeof body === "object" && !Array.isArray(body) ? body : {}) as FormBody;
  }
  return await context.req.parseBody().catch(() => ({})) as FormBody;
}

export const deviceFlowRoutes = new Hono<{ Bindings: Env }>();

function enabled(env: Env): boolean {
  return env.ENABLE_DEVICE_FLOW === "true";
}

const FORM_HEADERS = { "Cache-Control": "no-store" };

async function audit(env: Env, event: Omit<Parameters<typeof insertAuditEvent>[1], "id">): Promise<void> {
  await insertAuditEvent(env, { id: crypto.randomUUID(), ...event });
}

/** RFC 8628 §3.1: the device posts client_id (+ optionally credentials here
 * unsupported — only public clients are admitted, confidential ones must go
 * through an authenticated variant). */
deviceFlowRoutes.post("/api/auth/oauth2/device/authorize", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const form = (await formBody(context)) as FormBody;
  const clientId = typeof form.client_id === "string" ? form.client_id : "";
  const scope = typeof form.scope === "string" ? form.scope : "";
  if (!clientId || clientId.length > 200) {
    return context.json({ error: "invalid_client" }, 400, FORM_HEADERS);
  }
  if (!scope || scope.length > 512) {
    return context.json({ error: "invalid_scope", error_description: "scope is required" }, 400, FORM_HEADERS);
  }
  const client = await loadRegisteredClient(env, clientId);
  if (!client || client.disabled || !clientAllowsGrant(client.grantTypes, "urn:ietf:params:oauth:grant-type:device_code")) {
    return context.json({ error: "unauthorized_client" }, 400, FORM_HEADERS);
  }
  const requestedScopes = scope.split(" ").filter((entry) => entry.length > 0);
  const allowedScopes = client.scopes;
  if (allowedScopes && allowedScopes.length > 0 && requestedScopes.some((entry: string) => !allowedScopes.includes(entry))) {
    return context.json({ error: "invalid_scope" }, 400, FORM_HEADERS);
  }
  const issuance = await createDeviceGrant(env, clientId, requestedScopes).catch(() => null);
  if (!issuance) {
    // The cap rejects hoarding clients; a storage failure is transient.
    return context.json({ error: "invalid_request", error_description: "Device registration is temporarily unavailable" }, 429, FORM_HEADERS);
  }
  const verificationUri = `${new URL(env.AUTH_BASE_URL).origin}/device`;
  await audit(env, { actor_user_id: null, target_user_id: null,
    event_type: "authentication.device_flow.authorize", outcome: "success", request_path: "/api/auth/oauth2/device/authorize" });
  return context.json({
    device_code: issuance.deviceCode,
    user_code: issuance.userCode,
    verification_uri: verificationUri,
    verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(issuance.userCode)}`,
    expires_in: issuance.expiresInSeconds,
    interval: issuance.intervalSeconds,
  }, 200, FORM_HEADERS);
});

/** State query for the approval page: pending grant details for one code.
 * Session-required: only a signed-in user learns what a code is for, so the
 * endpoint cannot be probed without a portal session. */
deviceFlowRoutes.post("/api/device/flow/verify", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const auth = createAuth(env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "unauthorized" }, 401);
  const form = (await formBody(context).catch(() => ({}))) as Record<string, unknown>;
  const userCodeRaw = form.user_code as string | undefined;
  const userCode = typeof userCodeRaw === "string" ? normalizeUserCode(userCodeRaw) : "";
  if (!userCode || userCode.length > 16) {
    await audit(env, { actor_user_id: null, target_user_id: null,
      event_type: "authentication.device_flow.verify_failed", outcome: "failure", request_path: "/api/device/flow/verify" });
    return context.json({ error: "invalid_request" }, 400);
  }
  const grant = await loadDeviceGrantByUserCode(env, userCode).catch(() => null);
  if (!grant) {
    await audit(env, { actor_user_id: null, target_user_id: null,
      event_type: "authentication.device_flow.verify_failed", outcome: "failure", request_path: "/api/device/flow/verify" });
    return context.json({ error: "invalid_request", error_description: "Unknown or expired user code" }, 404);
  }
  if (grant.status !== "pending") {
    return context.json({ error: "invalid_request", error_description: "This request was already decided" }, 409);
  }
  const client = await loadRegisteredClient(env, grant.clientId);
  return context.json({
    client_name: client?.name ?? grant.clientId,
    scopes: grant.scopes,
    expires_in: Math.max(0, Math.floor((grant.expiresAt - Date.now()) / 1000)),
  });
});

async function decide(context: Context<{ Bindings: Env }>, approve: boolean): Promise<Response> {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const auth = createAuth(env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "unauthorized" }, 401);
  const form = (await formBody(context).catch(() => ({}))) as Record<string, unknown>;
  const userCodeRaw = form.user_code as string | undefined;
  const userCode = typeof userCodeRaw === "string" ? normalizeUserCode(userCodeRaw) : "";
  if (!userCode) return context.json({ error: "invalid_request" }, 400);
  if (approve) {
    try {
      const grant = await loadDeviceGrantByUserCode(env, userCode);
      if (!grant || grant.status !== "pending") return context.json({ error: "invalid_request" }, 409);
      const denied = await checkOidcAccess(env, grant.clientId, session);
      if (denied) return denied;
    } catch {
      return context.json({ error: "Authorization policy unavailable" }, 503);
    }
  }
  const decided = await decideDeviceGrant(env, userCode, approve, session.user.id, session.session.id).catch(() => false);
  await audit(env, {
    actor_user_id: session.user.id, target_user_id: session.user.id,
    event_type: approve ? "authentication.device_flow.approved" : "authentication.device_flow.denied",
    outcome: decided ? "success" : "failure",
    request_path: "/api/device/flow/approve",
  });
  if (!decided) return context.json({ error: "invalid_request", error_description: "Unknown, expired, or already-decided request" }, 409);
  return context.json({ status: approve ? "approved" : "denied" });
}

deviceFlowRoutes.post("/api/device/flow/approve", async (context) => decide(context, true));

deviceFlowRoutes.post("/api/device/flow/deny", async (context) => decide(context, false));
