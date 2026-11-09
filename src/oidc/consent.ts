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

export const consentRoutes = new Hono<{ Bindings: Env }>();

consentRoutes.get("/consent", async (context) => {
  const query = new URL(context.req.url).searchParams;
  const oauthQuery = query.toString();
  if (oauthQuery.length === 0 || !oauthQuery.includes("client_id=")) {
    return context.json({ error: "The single sign-on request cannot be processed" }, 400);
  }
  const scopes = (query.get("scope") ?? "").split(" ").filter(Boolean);
  const clientId = query.get("client_id") ?? "";
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  context.header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
  );
  return context.body(consentPage(clientId, scopes, oauthQuery), 200, {
    "Content-Type": "text/html; charset=utf-8",
  });
});

function consentPage(clientId: string, scopes: string[], oauthQuery: string): string {
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
    '<script>var Q=document.getElementById("f").elements["oauth_query"].value;var A=document.getElementById("a");var D=document.getElementById("d");var E=document.getElementById("error");',
    "var SC=[", scopes.map((scope) => JSON.stringify(scope)).join(","), "];",
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
