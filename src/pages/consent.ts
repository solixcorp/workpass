/**
 * OIDC consent page: completes the authorization-code flow this Worker
 * advertises. The authorization endpoint redirects authenticated users here
 * with a tamper-proofed, signed oauth query; approving sends that signed
 * query back to the native consent endpoint, which verifies the signature,
 * so parameters cannot be forged or swapped by the page or the user. The
 * approval call is a same-origin browser fetch, not a server-side proxy:
 * workerd refuses self-fetches, and the client's own origin is what the
 * consent check trusts.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { evaluateAppAccess, hasRecentAppIssuance, loadAppAccessPolicy } from "../access/policies";

export const consentRoutes = new Hono<{ Bindings: Env }>();

consentRoutes.get("/consent", async (context) => {
  const query = new URL(context.req.url).searchParams;
  const oauthQuery = query.toString();
  if (oauthQuery.length === 0 || !oauthQuery.includes("client_id=")) {
    return context.json({ error: "The single sign-on request cannot be processed" }, 400);
  }
  const scopes = (query.get("scope") ?? "").split(" ").filter(Boolean);
  const clientId = query.get("client_id") ?? "";
  // The per-application access policy: group gating at the consent step.
  const policySubject = `oidc:${clientId}`;
  let gate = { allowed: true, observedOnly: false, priorSuccess: false };
  try {
    const policy = await loadAppAccessPolicy(context.env, policySubject);
    if (policy) {
      const session = await (await import("../auth/config")).createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
      const evaluation = await evaluateAppAccess(context.env, policy, session?.user.id ?? "");
      const priorSuccess = session?.user.id
        ? await hasRecentAppIssuance(context.env, policySubject, session.user.id, policy.bypassWindowSeconds)
        : false;
      gate = { allowed: evaluation.allowed, observedOnly: evaluation.observedOnly, priorSuccess };
    }
  } catch {
    return context.json({ error: "Authorization policy unavailable" }, 503);
  }
  if (!gate.allowed) {
    return context.redirect(`${new URL(context.env.AUTH_BASE_URL).origin}/api/auth/error?error=access_denied`, 302);
  }
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  context.header(
    "Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; form-action 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'`,
  );
  return context.body(consentPage(clientId, scopes, oauthQuery, nonce), 200, {
    "Content-Type": "text/html; charset=utf-8",
  });
});

function consentPage(clientId: string, scopes: string[], oauthQuery: string, nonce: string): string {
  const scopeList = scopes.length === 0
    ? "<li>your identity</li>"
    : scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("");
  return [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/>',
    "<title>Continue to your application</title>",
    "<style>",
    "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
    "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(340px,90vw)}",
    "h1{font-size:17px;margin:0 0 8px}",
    "p,li{font-size:13px;color:#3c3c44}",
    "button{margin-top:16px;margin-right:8px;padding:10px 14px;border:0;border-radius:6px;font-size:14px;cursor:pointer}",
    ".accept{background:#2f5fe0;color:#fff}.deny{background:#e4e4e9;color:#3c3c44}",
    "#error{color:#b3261e;font-size:13px;margin-top:12px;min-height:16px}",
    "</style></head><body><main>",
    "<h1>Continue to your application</h1>",
    `<p>The application (${escapeHtml(clientId)}) requests:</p>`,
    `<ul>${scopeList}</ul>`,
    '<form id="f" method="post">',
    `<input type="hidden" name="oauth_query" value="${escapeHtml(oauthQuery)}"/>`,
    '<button class="accept" id="a" name="decision" type="submit" value="accept">Continue</button>',
    '<button class="deny" id="d" name="decision" type="submit" value="deny">No, do not continue</button>',
    '<div id="error" role="alert"></div>',
    "</form></main>",
    `<script nonce="${nonce}">var Q=document.getElementById("f").elements["oauth_query"].value;var A=document.getElementById("a");var D=document.getElementById("d");var E=document.getElementById("error");`,
    "var SC=new URLSearchParams(Q).get('scope')?.split(' ').filter(Boolean)||[];",
    "function send(accept,button){A.disabled=true;D.disabled=true;E.textContent='';",
    "fetch('/api/auth/oauth2/consent',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','Accept':'application/json'},",
    "body:JSON.stringify({oauth_query:Q,accept:accept,scopes:SC})})",
    ".then(function(r){return r.json().then(function(j){return {status:r.status,json:j};},function(){return {status:r.status,json:{}};});})",
    ".then(function(up){",
    "var target=up.json.redirectURI||up.json.url;",
    "if(up.status>=200&&up.status<400&&target){location.href=target;return;}",
    "A.disabled=false;D.disabled=false;",
    "E.textContent=up.status===403?'This sign-in request is not authorized to continue.':(up.status===401?'Sign in first, then try again.':'This sign-in request cannot be processed. Ask the application for a new one.');",
    "})",
    ".catch(function(){A.disabled=false;D.disabled=false;E.textContent='This sign-in request cannot be processed. Ask the application for a new one.';});}",
    "A.addEventListener('click',function(ev){ev.preventDefault();send(true,A);});",
    "D.addEventListener('click',function(ev){ev.preventDefault();send(false,D);});",
    "</script></body></html>",
  ].join("");
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&apos;";
    }
  });
}
