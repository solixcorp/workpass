/**
 * RFC 8628 Device Authorization Grant — authorization endpoint, human approval
 * surface, and the verification page. Routes fail closed behind
 * ENABLE_DEVICE_FLOW. The device hits POST /oauth2/device/authorize (public,
 * client_id + scope); the human opens GET /device, signs in if needed, types
 * the user code, and approves or denies. Approval binds the grant to the
 * approving user and session; the token grant (src/oauth/extended-grants.ts)
 * consumes it exactly once.
 */

import { Hono, type Context } from "hono";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { createAuth } from "../auth/config";
import {
  createDeviceGrant, decideDeviceGrant, loadDeviceGrantByUserCode, normalizeUserCode,
} from "./device-flow";
import { clientAllowsGrant, loadRegisteredClient } from "./client-registry";

type FormBody = Record<string, string | File>;

async function formBody(context: Context<{ Bindings: Env }>): Promise<FormBody> {
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

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function page(nonce: string, body: string): string {
  return [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>',
    "<title>Device sign in</title>",
    "<style>",
    "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
    "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(360px,90vw)}",
    "h1{font-size:17px;margin:0 0 8px}p,li{font-size:13px;color:#3c3c44}",
    "label{display:block;font-size:12px;margin:10px 0 4px}",
    "input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfcfd8;border-radius:6px;font-size:14px;text-transform:uppercase}",
    "button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:6px;background:#2f5fe0;color:#fff;font-size:14px;cursor:pointer}",
    ".danger{background:#b3261e}#error{color:#b3261e;font-size:13px;margin-top:12px;min-height:16px}",
    "code{background:#f0f0f4;padding:1px 5px;border-radius:4px;font-size:12px}",
    "</style></head><body><main>",
    body,
    `<script nonce="${nonce}">`,
    "</script></main></body></html>",
  ].join("\n");
}

function nonceContext(): string {
  const buffer = crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const byte of buffer) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function securePageHeaders(context: { header: (name: string, value: string) => void }, nonce: string): void {
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  context.header("Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; form-action 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'`);
}

function scopeList(scopes: string[]): string {
  return scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join("");
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

/** The human surface: enter the user code, review the request, decide.
 * Unauthenticated visits never collect credentials here: the user signs in
 * through the organization's normal portal first, then reopens the
 * verification link. */
deviceFlowRoutes.get("/device", async (context) => {
  const env = context.env;
  if (!enabled(env)) return context.notFound();
  const auth = createAuth(env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) {
    const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
    let nonceBinary = "";
    for (const byte of nonceBytes) nonceBinary += String.fromCharCode(byte);
    const nonce = btoa(nonceBinary);
    context.header("Cache-Control", "no-store");
    context.header("Referrer-Policy", "no-referrer");
    context.header("Content-Security-Policy",
      `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'`);
    return context.body([
      "<!DOCTYPE html>",
      '<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>',
      "<title>Device sign in</title>",
      "<style>",
      "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
      "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(360px,90vw)}",
      "h1{font-size:17px;margin:0 0 8px}p{font-size:13px;color:#3c3c44}",
      "</style></head><body><main>",
      "<h1>Device sign in</h1>",
      "<p>First sign in through your organization's sign-in portal, then reopen the verification link from your device.</p>",
      "<p>This page never asks for your password. The code expires in 10 minutes.</p>",
      "</main></body></html>",
    ].join("\n"), 403, { "Content-Type": "text/html; charset=utf-8" });
  }
  const prefilled = normalizeUserCode(context.req.query("user_code") ?? "").slice(0, 16);
  const nonce = nonceContext();
  securePageHeaders(context, nonce);
  const body = [
    "<h1>Device sign in</h1>",
    "<p>Enter the code shown on your device.</p>",
    '<form id="f" autocomplete="off">',
    '<label for="user_code">Device code</label>',
    `<input id="user_code" value="${escapeHtml(prefilled)}" ${prefilled ? "readonly" : ""}/>`,
    '<button id="v" type="submit">Continue</button>',
    "</form>",
    '<div id="request" hidden>',
    '<p id="request_text"></p>',
    '<ul id="scopes"></ul>',
    '<button id="a" type="button">Approve</button>',
    '<button id="d" type="button" class="danger">Deny</button>',
    "</div>",
    '<p id="done" hidden></p>',
    '<div id="error" role="alert"></div>',
    `<script nonce="${nonce}">` +
    "var f=document.getElementById('f'),v=document.getElementById('v'),er=document.getElementById('error');" +
    "var rq=document.getElementById('request'),tx=document.getElementById('request_text'),ul=document.getElementById('scopes');" +
    "var dn=document.getElementById('done');" +
    "function post(url,data){return fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(data)}).then(function(r){return r.json().then(function(j){return {status:r.status,json:j};},function(){return {status:r.status,json:{}};});});}" +
    "function esc(s){var d=document.createElement('span');d.textContent=s;return d.innerHTML;}" +
    "f.addEventListener('submit',function(ev){ev.preventDefault();v.disabled=true;er.textContent='';" +
    "var code=document.getElementById('user_code').value;" +
    "post('/api/device/flow/verify',{user_code:code}).then(function(res){if(res.status!==200){v.disabled=false;er.textContent=res.json.error_description||'That code is not valid.';return;}" +
    "f.hidden=true;rq.hidden=false;" +
    "tx.innerHTML='The device <strong>'+esc(res.json.client_name)+'</strong> requests access with scopes:';" +
    "ul.innerHTML=res.json.scopes.map(function(s){return '<li><code>'+esc(s)+'</code></li>';}).join('');" +
    "window.__code=code;});});" +
    "document.getElementById('a').addEventListener('click',function(){decide(true)});" +
    "document.getElementById('d').addEventListener('click',function(){decide(false)});" +
    "function decide(approve){er.textContent='';" +
    "post(approve?'/api/device/flow/approve':'/api/device/flow/deny',{user_code:window.__code}).then(function(res){" +
    "if(res.status!==200){er.textContent=res.json.error_description||'The decision failed.';return;}" +
    "rq.hidden=true;dn.hidden=false;dn.textContent=approve?'Access approved. You can return to your device.':'Request denied.';});});" +
    "</script>",
  ];
  return context.body(page(nonce, body.join("\n")), 200, { "Content-Type": "text/html; charset=utf-8" });
});
