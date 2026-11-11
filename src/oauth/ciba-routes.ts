/**
 * OpenID CIBA poll mode — backchannel authentication endpoint and the human
 * approval surface. Routes fail closed behind ENABLE_CIBA. The client posts
 * the request (client_secret_basic/post — confidential clients only; see the
 * design doc), the user acts on /ciba (the single-page app, or through the email notification)
 * and the token grant (src/oauth/extended-grants.ts) consumes the decision.
 */

import { Hono, type Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { sendTransactionEmail, transactionEmailAvailable } from "../mail/send";
import { createAuth } from "../auth/config";
import {
  createCibaRequest, decideCibaRequest, listPendingCibaRequests,
  normalizeBindingMessage, CIBA_REQUEST_TTL_SECONDS,
} from "./ciba";
import { clientAllowsGrant, loadRegisteredClient, matchesStoredClientSecret } from "./client-registry";

type FormBody = Record<string, string | File>;

/** Clients post forms; the approval page posts JSON. */
async function formBody(context: Context<{ Bindings: Env }>): Promise<FormBody> {
  if ((context.req.header("content-type") ?? "").includes("application/json")) {
    const body = await context.req.json().catch(() => ({})) as unknown;
    return (body && typeof body === "object" && !Array.isArray(body) ? body : {}) as FormBody;
  }
  return await context.req.parseBody().catch(() => ({})) as FormBody;
}

export const cibaRoutes = new Hono<{ Bindings: Env }>();

const FORM_HEADERS = { "Cache-Control": "no-store" };

function enabled(env: Env): boolean {
  return env.ENABLE_CIBA === "true";
}

async function audit(env: Env, event: Omit<Parameters<typeof insertAuditEvent>[1], "id">): Promise<void> {
  await insertAuditEvent(env, { id: crypto.randomUUID(), ...event });
}

function cibaError(context: Context<{ Bindings: Env }>, status: ContentfulStatusCode, error: string, description?: string): Response {
  return context.json(description ? { error, error_description: description } : { error }, status, FORM_HEADERS);
}

interface ClientCredentials {
  clientId: string;
  secret: string | undefined;
  /** Which channel the credentials arrived on: "basic" or "post". */
  method: "client_secret_basic" | "client_secret_post";
}

/** client_secret_basic / client_secret_post extraction (§8). Only these two
 * confidential channels are honored; the registered method must match, mirroring
 * the provider's token-endpoint behavior. */
async function extractClientCredentials(context: Context<{ Bindings: Env }>): Promise<ClientCredentials> {
  const header = context.req.header("authorization") ?? "";
  if (header.startsWith("Basic ")) {
    const decoded = atob(header.slice(6).trim());
    const separator = decoded.indexOf(":");
    if (separator > 0) {
      return { clientId: decodeURIComponent(decoded.slice(0, separator).replaceAll("%20", " ")), secret: decodeURIComponent(decoded.slice(separator + 1).replaceAll("%20", " ")), method: "client_secret_basic" };
    }
    return { clientId: "", secret: undefined, method: "client_secret_basic" };
  }
  const form = await formBody(context);
  if (typeof form.client_id === "string") {
    return {
      clientId: form.client_id,
      secret: typeof form.client_secret === "string" ? form.client_secret : undefined,
      method: form.client_secret !== undefined ? "client_secret_post" : "client_secret_basic",
    };
  }
  return { clientId: "", secret: undefined, method: "client_secret_post" };
}

/** OpenID CIBA Core §7.1 backchannel authentication endpoint. */
cibaRoutes.post("/api/auth/oauth2/bc-authorize", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const credentials = await extractClientCredentials(context);
  if (!credentials.clientId || credentials.clientId.length > 200) {
    return cibaError(context, 401, "invalid_client");
  }
  const client = await loadRegisteredClient(env, credentials.clientId);
  if (!client || client.disabled) return cibaError(context, 401, "invalid_client");
  // CIBA clients are confidential; public clients are not a CIBA surface.
  // Assertion methods (private_key_jwt…) are not honored at this endpoint yet.
  if (client.tokenEndpointAuthMethod === "none" || !client.clientSecretHash) {
    return cibaError(context, 401, "invalid_client");
  }
  if (client.tokenEndpointAuthMethod !== null &&
      client.tokenEndpointAuthMethod !== "client_secret_basic" &&
      client.tokenEndpointAuthMethod !== "client_secret_post") {
    return cibaError(context, 401, "invalid_client");
  }
  const secretMatches = await matchesStoredClientSecret(credentials.secret ?? "", client.clientSecretHash);
  // The credential channel must match the registration, like the token endpoint.
  if (!credentials.secret || !secretMatches || credentials.method !== client.tokenEndpointAuthMethod) {
    await audit(env, { actor_user_id: null, target_user_id: null,
      event_type: "authentication.ciba.client_auth_failed", outcome: "failure",
      request_path: "/api/auth/oauth2/bc-authorize" });
    return cibaError(context, 401, "invalid_client");
  }
  if (!clientAllowsGrant(client.grantTypes, "urn:openid:params:grant-type:ciba")) {
    return cibaError(context, 403, "unauthorized_client");
  }
  const form = await formBody(context);
  const loginHint = typeof form.login_hint === "string" ? form.login_hint.trim() : "";
  const scope = typeof form.scope === "string" ? form.scope : "";
  if (!loginHint || loginHint.length > 256 || !scope) {
    return cibaError(context, 400, "invalid_request", "scope and login_hint are required");
  }
  const requestedScopes = scope.split(" ").filter((entry) => entry.length > 0);
  if (client.scopes && client.scopes.length > 0 && requestedScopes.some((entry) => !client.scopes!.includes(entry))) {
    return cibaError(context, 400, "invalid_scope");
  }
  const bindingMessage = normalizeBindingMessage(typeof form.binding_message === "string" ? form.binding_message : undefined);
  const users = await env.DB.prepare(
    `SELECT id, banned FROM "user" WHERE email = ? OR username = ? ORDER BY (email = ?) DESC LIMIT 2`,
  ).bind(loginHint, loginHint, loginHint).all<{ id: string; banned: number | null }>();
  const user = users.results.length === 1 ? users.results[0] : null;
  // Fail closed: an ambiguous or banned identity never starts a request.
  if (!user || (user.banned !== 0 && user.banned !== null)) {
    await audit(env, { actor_user_id: null, target_user_id: null,
      event_type: "authentication.ciba.unknown_or_banned_user", outcome: "failure",
      request_path: "/api/auth/oauth2/bc-authorize" });
    return cibaError(context, 400, "unknown_user_id");
  }
  const issuance = await createCibaRequest(env, {
    clientId: credentials.clientId, userId: user.id, scopes: requestedScopes, bindingMessage,
  }).catch(() => null);
  if (!issuance) return cibaError(context, 429, "invalid_request", "Too many pending approval requests");
  // Notification is best-effort: email carries the pointer, the /ciba page
  // always lists pending requests. A delivery failure is audited, not fatal.
  if (transactionEmailAvailable(env)) {
    try {
      const emailRow = await env.DB.prepare('SELECT email FROM "user" WHERE id = ?').bind(user.id)
        .first<{ email: string }>();
      if (emailRow) {
        await sendTransactionEmail(env, {
          to: emailRow.email,
          subject: "Application access request",
          text: `An application requested access${bindingMessage ? `: "${bindingMessage}"` : ""}. Review it at ${new URL(env.AUTH_BASE_URL).origin}/ciba within ${Math.round(CIBA_REQUEST_TTL_SECONDS / 60)} minutes.`,
        });
      }
    } catch (error) {
      console.error("CIBA notification email failed", { name: error instanceof Error ? error.name : "UnknownError" });
    }
  }
  await audit(env, { actor_user_id: user.id, target_user_id: user.id,
    event_type: "authentication.ciba.request_created", outcome: "success",
    request_path: "/api/auth/oauth2/bc-authorize" });
  return context.json({ auth_req_id: issuance.authReqId, expires_in: issuance.expiresInSeconds,
    interval: issuance.intervalSeconds }, 200, FORM_HEADERS);
});

/** The signed-in user's pending requests, for the approval page. */
cibaRoutes.get("/api/ciba/pending", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const session = await createAuth(env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return cibaError(context, 401, "invalid_request", "Sign in through your organization's portal first");
  const pending = await listPendingCibaRequests(env, session.user.id);
  const clients = await Promise.all(pending.map((request) => loadRegisteredClient(env, request.clientId)));
  return context.json({
    requests: pending.map((request, index) => ({
      id: request.id,
      clientName: clients[index]?.name ?? request.clientId,
      scopes: request.scopes,
      bindingMessage: request.bindingMessage || null,
      expiresAt: request.expiresAt,
    })),
  }, 200, FORM_HEADERS);
});

/** The approval page posts here; a plain form post still works and goes back to /ciba. */
cibaRoutes.post("/api/ciba/decide", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const auth = createAuth(env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return cibaError(context, 401, "invalid_request", "Sign in through your organization's portal first");
  const form = await formBody(context);
  const requestId = typeof form.request === "string" ? form.request : "";
  const decision = form.decision;
  if (!requestId || requestId.length > 64 || (decision !== "approve" && decision !== "deny")) {
    return cibaError(context, 400, "invalid_request");
  }
  const approve = decision === "approve";
  const decided = await decideCibaRequest(env, requestId, session.user.id, approve, session.session.id).catch(() => false);
  await audit(env, {
    actor_user_id: session.user.id, target_user_id: session.user.id,
    event_type: approve ? "authentication.ciba.approved" : "authentication.ciba.denied",
    outcome: decided ? "success" : "failure",
    request_path: "/api/ciba/decide",
  });
  if ((context.req.header("content-type") ?? "").includes("application/json")) {
    return decided
      ? context.json({ status: approve ? "approved" : "denied" }, 200, FORM_HEADERS)
      : cibaError(context, 409, "invalid_request", "Unknown, expired, or already-decided request");
  }
  return context.redirect("/ciba", 303);
});
