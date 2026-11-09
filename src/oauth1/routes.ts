/**
 * OAuth 1.0a authorization server (RFC 5849, HMAC-SHA1 profile). Disabled
 * unless ENABLE_OAUTH1=true. Consumer registration is operator-token gated.
 * The flow is 3-legged: initiate (temporary credentials) → browser authorize
 * (signed-in user approves/denies) → token exchange (verifier single-use).
 * Access tokens are issued for the platform's own users; resource endpoints
 * authenticate with verifyOAuth1Request + resolveOAuth1AccessToken.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { constantTimeTokenMatches } from "../security/tokens";
import { verifyOAuth1Request } from "./verify";
import {
  approveTemporaryToken, createConsumer, ensureOAuth1Tables, issueAccessToken,
  issueTemporaryToken, loadTemporaryToken, rejectTemporaryToken, resolveOAuth1AccessToken,
  resolveOAuth1Consumer, revokeOAuth1AccessToken, setConsumerDisabled,
} from "./store";

export const oauth1Routes = new Hono<{ Bindings: Env }>();

function enabled(env: Env): boolean {
  return env.ENABLE_OAUTH1 === "true";
}

function form(values: Record<string, string>): Response {
  return new Response(new URLSearchParams(values).toString(), {
    status: 200,
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-store" },
  });
}

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
    "<title>Continue to the application</title>",
    "<style>",
    "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
    "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(360px,90vw)}",
    "h1{font-size:17px;margin:0 0 8px}p,li{font-size:13px;color:#3c3c44}",
    "label{display:block;font-size:12px;margin:10px 0 4px}",
    "input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfcfd8;border-radius:6px;font-size:14px}",
    "button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:6px;background:#2f5fe0;color:#fff;font-size:14px;cursor:pointer}",
    ".danger{background:#b3261e}#error{color:#b3261e;font-size:13px;margin-top:12px;min-height:16px}",
    "</style></head><body><main>",
    body,
    `<script nonce="${nonce}">`,
    "</script></main></body></html>",
  ].join("\n");
}

/** Management: operator-provisioned consumers. Fails closed. */
oauth1Routes.post("/api/oauth1/consumers", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  const token = (context.req.header("authorization") ?? "").replace(/^Bearer /, "");
  if (!context.env.OAUTH1_MANAGEMENT_TOKEN || !constantTimeTokenMatches(token, context.env.OAUTH1_MANAGEMENT_TOKEN)) {
    return context.json({ error: "Unauthorized" }, 401);
  }
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const consumerName = (body as { consumer_name?: unknown } | null)?.consumer_name;
  if (typeof consumerName !== "string" || consumerName.trim().length === 0 || consumerName.length > 128) {
    return context.json({ error: "consumer_name is required" }, 400);
  }
  try {
    const consumer = await createConsumer(context.env, consumerName.trim());
    await audit(context.env, { actor_user_id: null, target_user_id: null,
      event_type: "oauth1.consumer.register", outcome: "success", request_path: "/api/oauth1/consumers" });
    return context.json({
      consumer_key: consumer.consumerKey,
      consumer_secret: consumer.consumerSecret,
      consumer_name: consumer.consumerName,
    }, 201);
  } catch (error) {
    if (error instanceof Error && error.message === "AEAD_SEALING_KEY must be configured for sealed storage") {
      return context.json({ error: "Sealed storage is not configured" }, 503);
    }
    return context.json({ error: "Consumer registration failed" }, 500);
  }
});

oauth1Routes.patch("/api/oauth1/consumers/:key", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  const token = (context.req.header("authorization") ?? "").replace(/^Bearer /, "");
  if (!context.env.OAUTH1_MANAGEMENT_TOKEN || !constantTimeTokenMatches(token, context.env.OAUTH1_MANAGEMENT_TOKEN)) {
    return context.json({ error: "Unauthorized" }, 401);
  }
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const disabled = (body as { disabled?: unknown } | null)?.disabled;
  if (typeof disabled !== "boolean") return context.json({ error: "disabled must be a boolean" }, 400);
  const updated = await setConsumerDisabled(context.env, context.req.param("key"), disabled).catch(() => null);
  if (updated === null) return context.json({ error: "Consumer update failed" }, 500);
  if (!updated) return context.json({ error: "Consumer not found" }, 404);
  await audit(context.env, { actor_user_id: null, target_user_id: null,
    event_type: disabled ? "oauth1.consumer.disable" : "oauth1.consumer.enable",
    outcome: "success", request_path: "/api/oauth1/consumers" });
  return context.json({ status: disabled ? "disabled" : "enabled" });
});

/** RFC 5849 §2.3 Temporary Credential Request. */
oauth1Routes.post("/api/oauth1/initiate", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  await ensureOAuth1Tables(context.env.DB);
  const verified = await verifyOAuth1Request(context.req.raw, {
    resolveCredential: async (consumerKey, token) => {
      if (token !== undefined) return null; // initiate is consumer-only.
      const consumer = await resolveOAuth1Consumer(context.env, consumerKey);
      return consumer ? { consumerSecret: consumer.consumerSecret } : null;
    },
    claimNonce: async (consumerKey, token, timestamp, nonce) => {
      const { claimOAuth1Nonce } = await import("./nonce-store");
      return claimOAuth1Nonce(context.env.DB, consumerKey, token, timestamp, nonce);
    },
  });
  if (verified === null) {
    return context.json({ error: "Invalid OAuth 1.0 request" }, 401);
  }
  const callback = new Map(verified.parameters).get("oauth_callback");
  if (callback !== undefined) {
    if (callback !== "oob") {
      try {
        const url = new URL(callback);
        if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("scheme");
        if (callback.length > 2048) throw new Error("length");
      } catch {
        return context.json({ error: "oauth_callback must be an http(s) URI or oob" }, 400);
      }
    }
  } else {
    return context.json({ error: "oauth_callback is required" }, 400);
  }
  const issued = await issueTemporaryToken(context.env, verified.consumerKey, callback ?? "oob");
  await audit(context.env, { actor_user_id: null, target_user_id: null,
    event_type: "oauth1.temporary.issue", outcome: "success", request_path: "/api/oauth1/initiate" });
  return form({ oauth_token: issued.token, oauth_token_secret: issued.secret, oauth_callback_confirmed: "true" });
});

/** Browser step: the signed-in user approves or denies the consumer. */
oauth1Routes.get("/api/oauth1/authorize", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  await ensureOAuth1Tables(context.env.DB);
  const oauthToken = context.req.query("oauth_token") ?? "";
  if (!oauthToken || oauthToken.length > 512) return context.json({ error: "oauth_token is required" }, 400);
  const pending = await loadTemporaryToken(context.env, oauthToken);
  if (!pending || pending.expired || pending.approved) {
    return context.json({ error: "This authorization request is no longer valid" }, 400);
  }
  const consumer = await resolveOAuth1Consumer(context.env, pending.consumerKey);
  if (!consumer) return context.json({ error: "This application is not available" }, 400);

  const auth = (await import("../auth/config")).createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) {
    return context.redirect(context.req.url.replace("/authorize", "/authorize/login"), 302);
  }

  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  context.header("Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; form-action 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'`);
  const bodyParts = [
    "<h1>Continue to the application</h1>",
    `<p>The application <strong>${escapeHtml(consumer.consumerName)}</strong> requests access to your account identity.</p>`,
    `<p>Signed in as <strong>${escapeHtml(session.user.email ?? session.user.id)}</strong>.</p>`,
    '<form id="f" method="post" action="/api/oauth1/authorize/approve">',
    `<input type="hidden" name="oauth_token" value="${escapeHtml(pending.token)}"/>`,
    '<button id="a" name="decision" type="submit" value="approve">Continue</button>',
    '<button id="d" class="danger" name="decision" type="submit" value="deny">No, do not continue</button>',
    "</form>",
  ];
  return context.body(page(nonce, bodyParts.join("\n")), 200, { "Content-Type": "text/html; charset=utf-8" });
});

/** Minimal sign-in handoff for unauthenticated authorize visits. */
oauth1Routes.get("/api/oauth1/authorize/login", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  const oauthToken = context.req.query("oauth_token") ?? "";
  if (!oauthToken || oauthToken.length > 512) return context.json({ error: "oauth_token is required" }, 400);
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  context.header("Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'`);
  const bodyParts = [
    "<h1>Sign in to continue</h1>",
    '<p>Sign in to the internal identity platform to continue.</p>',
    '<form id="f">',
    '<label for="identifier">Email or username</label>',
    '<input id="identifier" required autocapitalize="off"/>',
    '<label for="password">Password</label>',
    '<input id="password" type="password" required/>',
    '<button id="b" type="submit">Continue</button>',
    '<div id="error" role="alert"></div>',
    "</form>",
  ];
  const script = [
    "var t=" + JSON.stringify(oauthToken) + ";",
    "document.getElementById('f').addEventListener('submit',function(ev){ev.preventDefault();",
    "var id=document.getElementById('identifier').value.trim();var pw=document.getElementById('password').value;",
    "var endpoint=/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(id)?'/api/auth/sign-in/email':'/api/auth/sign-in/username';",
    "var payload=endpoint==='/api/auth/sign-in/email'?{email:id,password:pw}:{username:id,password:pw};",
    "fetch(endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})",
    ".then(function(r){if(r.status!==200)return r.json().then(function(j){throw new Error(j.message||'Sign-in failed')});return r.json()})",
    ".then(function(){location.replace('/api/oauth1/authorize?oauth_token='+encodeURIComponent(t))})",
    ".catch(function(er){document.getElementById('error').textContent=er.message||'Sign-in failed';document.getElementById('b').disabled=false;});});",
  ].join("\n");
  const rendered = [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>',
    "<title>Sign in to continue</title>",
    "<style>",
    "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
    "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(340px,90vw)}",
    "h1{font-size:17px;margin:0 0 8px}p{font-size:13px;color:#3c3c44}",
    "label{display:block;font-size:12px;margin:10px 0 4px}",
    "input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfcfd8;border-radius:6px;font-size:14px}",
    "button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:6px;background:#2f5fe0;color:#fff;font-size:14px;cursor:pointer}",
    "#error{color:#b3261e;font-size:13px;margin-top:12px;min-height:16px}",
    "</style></head><body><main>",
    bodyParts.join("\n"),
    `<script nonce="${nonce}">${script}</script>`,
    "</main></body></html>",
  ].join("\n");
  return context.body(rendered, 200, { "Content-Type": "text/html; charset=utf-8" });
});

async function redirectTarget(callback: string, params: Record<string, string>): Promise<string> {
  if (callback === "oob") return "";
  const url = new URL(callback);
  for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
  return url.toString();
}

function verifierPage(title: string, message: string, verifier: string | null): string {
  const parts = [
    "<h1>" + escapeHtml(title) + "</h1>",
    `<p>${escapeHtml(message)}</p>`,
  ];
  if (verifier) parts.push(`<p><strong>${escapeHtml(verifier)}</strong></p>`);
  parts.push("<p>You can close this window and return to the application.</p>");
  return [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/>',
    "<title>Continue to the application</title>",
    "</head><body><main>",
    parts.join("\n"),
    "</main></body></html>",
  ].join("\n");
}

oauth1Routes.post("/api/oauth1/authorize/approve", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  await ensureOAuth1Tables(context.env.DB);
  const auth = (await import("../auth/config")).createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const formData = await context.req.parseBody();
  const decision = formData["decision"];
  const oauthToken = formData["oauth_token"];
  if (typeof decision !== "string" || typeof oauthToken !== "string" || !oauthToken || oauthToken.length > 512) {
    return context.json({ error: "Invalid approval request" }, 400);
  }
  const pending = await loadTemporaryToken(context.env, oauthToken);
  if (!pending || pending.expired || pending.approved) {
    return context.json({ error: "This authorization request is no longer valid" }, 400);
  }
  if (decision === "deny") {
    await rejectTemporaryToken(context.env, pending.token);
    const denied = await redirectTarget(pending.callback, { denied: "1" });
    await audit(context.env, { actor_user_id: session.user.id, target_user_id: session.user.id,
      event_type: "oauth1.authorize.denied", outcome: "success", request_path: "/api/oauth1/authorize/approve" });
    if (denied) return context.redirect(denied, 302);
    return context.body(verifierPage("Authorization denied", "The application was not given access.", null), 200, { "Content-Type": "text/html; charset=utf-8" });
  }
  if (decision !== "approve") return context.json({ error: "Invalid decision" }, 400);
  const approved = await approveTemporaryToken(context.env, pending.token, session.user.id).catch(() => false);
  if (!approved) {
    await audit(context.env, { actor_user_id: session.user.id, target_user_id: session.user.id,
      event_type: "oauth1.authorize.approved", outcome: "failure", request_path: "/api/oauth1/authorize/approve" });
    return context.json({ error: "The approval could not be recorded" }, 503);
  }
  const redirect = await redirectTarget(pending.callback, { oauth_token: pending.token, oauth_verifier: pending.verifier });
  await audit(context.env, { actor_user_id: session.user.id, target_user_id: session.user.id,
    event_type: "oauth1.authorize.approved", outcome: "success", request_path: "/api/oauth1/authorize/approve" });
  if (redirect) return context.redirect(redirect, 302);
  return context.body(verifierPage("Approval complete",
    "Give this verification code to the application to finish connecting:", pending.verifier), 200, { "Content-Type": "text/html; charset=utf-8" });
});

/** RFC 5849 §2.3 Access Token Request: temp token + verifier → access token. */
oauth1Routes.post("/api/oauth1/token", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  await ensureOAuth1Tables(context.env.DB);
  const request = context.req.raw;
  const bodyParameters = new URLSearchParams(await request.clone().text().catch(() => ""));
  const oauthToken = bodyParameters.get("oauth_token")
    ?? (context.req.header("Authorization") ?? "").match(/oauth_token="([^"]+)"/)?.[1]
    ?? "";
  const oauthVerifier = bodyParameters.get("oauth_verifier") ?? "";
  const verified = await verifyOAuth1Request(request, {
    resolveCredential: async (consumerKey, token) => {
      if (token === undefined) return null;
      const consumer = await resolveOAuth1Consumer(context.env, consumerKey);
      if (!consumer) return null;
      const temporary = await loadTemporaryToken(context.env, token);
      if (!temporary || temporary.expired || temporary.secret === null || temporary.consumerKey !== consumerKey) return null;
      return { consumerSecret: consumer.consumerSecret, tokenSecret: temporary.secret };
    },
    claimNonce: async (consumerKey, token, timestamp, nonce) => {
      const { claimOAuth1Nonce } = await import("./nonce-store");
      return claimOAuth1Nonce(context.env.DB, consumerKey, token, timestamp, nonce);
    },
  });
  if (verified === null) {
    await audit(context.env, { actor_user_id: null, target_user_id: null,
      event_type: "oauth1.access.issue", outcome: "failure", request_path: "/api/oauth1/token" });
    return context.json({ error: "Invalid OAuth 1.0 request" }, 401);
  }
  const temporary = await loadTemporaryToken(context.env, verified.token ?? "");
  if (!temporary || temporary.secret === null || temporary.expired) {
    return context.json({ error: "The temporary token is no longer valid" }, 401);
  }
  const providedVerifier = oauthVerifier || new Map(verified.parameters).get("oauth_verifier") || "";
  if (!providedVerifier || providedVerifier.length > 512 || !constantTimeTokenMatches(providedVerifier, temporary.verifier)) {
    return context.json({ error: "oauth_verifier does not match" }, 401);
  }
  if (!temporary.approved || !temporary.userId) {
    return context.json({ error: "The temporary token has not been approved" }, 401);
  }
  const access = await issueAccessToken(context.env, verified.consumerKey, temporary.userId);
  // Single use: the receipt row is the exchange ticket.
  await rejectTemporaryToken(context.env, temporary.token);
  await audit(context.env, { actor_user_id: temporary.userId, target_user_id: temporary.userId,
    event_type: "oauth1.access.issue", outcome: "success", request_path: "/api/oauth1/token" });
  return form({ oauth_token: access.token, oauth_token_secret: access.secret });
});

/** RFC 5849 §2 access-token revocation equivalent. */
oauth1Routes.post("/api/oauth1/token/revoke", async (context) => {
  if (!enabled(context.env)) return context.notFound();
  await ensureOAuth1Tables(context.env.DB);
  const token = (context.req.header("authorization") ?? "").replace(/^Bearer /, "");
  if (!token || token.length > 512) return context.json({ error: "Invalid request" }, 400);
  const target = await resolveOAuth1AccessToken(context.env, token);
  const revoked = await revokeOAuth1AccessToken(context.env, token).catch(() => false);
  if (target) {
    await audit(context.env, { actor_user_id: target.userId, target_user_id: target.userId,
      event_type: "oauth1.access.revoke", outcome: revoked ? "success" : "failure", request_path: "/api/oauth1/token/revoke" });
  }
  return context.json({ status: revoked ? "revoked" : "unknown token" }, revoked ? 200 : 404);
});
