/**
 * OpenID CIBA poll mode — backchannel authentication endpoint and the human
 * approval surface. Routes fail closed behind ENABLE_CIBA. The client posts
 * the request (client_secret_basic/post — confidential clients only; see the
 * design doc), the user acts on GET /ciba (or through the email notification)
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

async function formBody(context: Context<{ Bindings: Env }>): Promise<FormBody> {
  return await formBody(context) as FormBody;
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
}

/** client_secret_basic / client_secret_post extraction (§8). */
async function extractClientCredentials(context: Context<{ Bindings: Env }>): Promise<ClientCredentials> {
  const header = context.req.header("authorization") ?? "";
  if (header.startsWith("Basic ")) {
    const decoded = atob(header.slice(6).trim());
    const separator = decoded.indexOf(":");
    if (separator > 0) {
      return { clientId: decodeURIComponent(decoded.slice(0, separator).replaceAll("%20", " ")), secret: decodeURIComponent(decoded.slice(separator + 1).replaceAll("%20", " ")) };
    }
  }
  const form = await formBody(context);
  if (typeof form.client_id === "string" && typeof form.client_secret === "string") {
    return { clientId: form.client_id, secret: form.client_secret };
  }
  if (typeof form.client_id === "string") return { clientId: form.client_id, secret: undefined };
  return { clientId: "", secret: undefined };
}

const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

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
  if (client.tokenEndpointAuthMethod === "none" || !client.clientSecretHash) {
    return cibaError(context, 401, "invalid_client");
  }
  const secretMatches = await matchesStoredClientSecret(credentials.secret ?? "", client.clientSecretHash);
  if (!credentials.secret || !secretMatches) {
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

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** The approval page: pending requests for the signed-in user. */
cibaRoutes.get("/ciba", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const auth = createAuth(env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.redirect("/sign-in", 302);
  const pending = await listPendingCibaRequests(env, session.user.id);
  const clients = await Promise.all(pending.map((request) => loadRegisteredClient(env, request.clientId)));
  const rows = pending.map((request, index) => {
    const clientName = escapeHtml(clients[index]?.name ?? request.clientId);
    const binding = request.bindingMessage
      ? `<p class="binding">&ldquo;${escapeHtml(request.bindingMessage)}&rdquo;</p>` : "";
    return [
      '<div class="request">',
      `<p>The application <strong>${clientName}</strong> requests access:</p>`,
      binding,
      `<ul>${request.scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join("")}</ul>`,
      `<form method="post" action="/api/ciba/decide">`,
      `<input type="hidden" name="request" value="${escapeHtml(request.id)}"/>`,
      '<button name="decision" value="approve" type="submit">Approve</button>',
      '<button name="decision" value="deny" type="submit" class="danger">Deny</button>',
      "</form></div>",
    ].join("\n");
  });
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  let nonceBinary = "";
  for (const byte of nonceBytes) nonceBinary += String.fromCharCode(byte);
  const nonce = btoa(nonceBinary);
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  context.header("Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`);
  const body = [
    "<h1>Application access requests</h1>",
    rows.length === 0
      ? "<p>No pending access requests.</p>"
      : `<p>Signed in as <strong>${escapeHtml(session.user.email ?? session.user.id)}</strong>.</p>${rows.join("\n")}`,
  ];
  return context.body([
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>',
    "<title>Application access requests</title>",
    "<style>",
    "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
    "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(420px,90vw)}",
    "h1{font-size:17px;margin:0 0 8px}p,li{font-size:13px;color:#3c3c44}",
    ".binding{font-style:italic}",
    ".request{border-top:1px solid #e4e4e9;margin-top:16px;padding-top:12px}",
    "button{margin-top:8px;padding:8px 14px;border:0;border-radius:6px;background:#2f5fe0;color:#fff;font-size:13px;cursor:pointer}",
    ".danger{background:#b3261e}",
    "code{background:#f0f0f4;padding:1px 5px;border-radius:4px;font-size:12px}",
    "</style></head><body><main>",
    body.join("\n"),
    "</main></body></html>",
  ].join("\n"), 200, { "Content-Type": "text/html; charset=utf-8" });
});

/** The form actions POST here (no JS: the page works without scripts). */
cibaRoutes.post("/api/ciba/decide", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const auth = createAuth(env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.redirect("/sign-in", 302);
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
  return context.redirect("/ciba", 303);
});
