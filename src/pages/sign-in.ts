/**
 * OIDC login handoff page: the authorization endpoint redirects unauthenticated
 * users here with a signed oauth query. After sign-in succeeds the page posts
 * that signed query back to the authorization endpoint, which verifies the
 * signature and continues the flow (consent or code). Parameters cannot be
 * forged or swapped: the query is tamper-proofed by the plugin's shared
 * secret, so the page only ever echoes what the IdP itself produced.
 *
 * This is a protocol completion page, not a portal dashboard.
 */

import { Hono } from "hono";
import type { Env } from "../env";

export const oidcSignInRoutes = new Hono<{ Bindings: Env }>();

oidcSignInRoutes.get("/sign-in", async (context) => {
  const query = new URL(context.req.url).searchParams;
  const oauthQuery = query.toString();
  const clientId = query.get("client_id") ?? "";
  const scopes = (query.get("scope") ?? "").split(" ").filter(Boolean);
  if (oauthQuery.length === 0 || !oauthQuery.includes("client_id=") || !oauthQuery.includes("sig=")) {
    // A bare /sign-in visit (no signed authorization continuation) is not a
    // startable flow: the authorization endpoint must originate it.
    return context.json({ error: "Sign-in must be started by an application" }, 400);
  }
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  context.header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
  );
  return context.body(signInHandoffPage(clientId, scopes, oauthQuery), 200, {
    "Content-Type": "text/html; charset=utf-8",
  });
});

function signInHandoffPage(clientId: string, scopes: string[], oauthQuery: string): string {
  const scopeList = scopes.length === 0
    ? "<li>your identity</li>"
    : scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("");
  return [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/>',
    "<title>Sign in to continue</title>",
    "<style>",
    "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
    "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(340px,90vw)}",
    "h1{font-size:17px;margin:0 0 8px}",
    "p,li{font-size:13px;color:#3c3c44}",
    "label{display:block;font-size:12px;margin:10px 0 4px;color:#3c3c44}",
    "input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfcfd8;border-radius:6px;font-size:14px}",
    "button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:6px;background:#2f5fe0;color:#fff;font-size:14px;cursor:pointer}",
    "button[disabled]{opacity:.6}",
    "#error{color:#b3261e;font-size:13px;margin-top:12px;min-height:16px}",
    "</style></head><body><main>",
    "<h1>Sign in to continue</h1>",
    `<p>The application (${escapeHtml(clientId)}) requests:</p>`,
    `<ul>${scopeList}</ul>`,
    '<form id="f" method="post" autocomplete="off">',
    '<label for="identifier">Email or username</label>',
    '<input id="identifier" name="identifier" type="text" required autocapitalize="off"/>',
    '<label for="password">Password</label>',
    '<input id="password" name="password" type="password" required/>',
    '<button id="b" type="submit">Continue</button>',
    '<div id="error" role="alert"></div>',
    "</form>",
    `<input type="hidden" id="q" value="${escapeHtml(oauthQuery)}"/>`,
    "</main>",
    '<script>var A="/api/auth/oauth2/authorize";var EMAIL="/api/auth/sign-in/email";var USER="/api/auth/sign-in/username";',
    "var f=document.getElementById('f'),b=document.getElementById('b'),e=document.getElementById('error');",
    "var Q=document.getElementById('q').value;",
    "f.addEventListener('submit',function(ev){ev.preventDefault();b.disabled=true;e.textContent='';",
    "var id=document.getElementById('identifier').value.trim();var pw=document.getElementById('password').value;",
    "var endpoint=/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(id)?EMAIL:USER;",
    "var payload=endpoint===EMAIL?{email:id,password:pw}:{username:id,password:pw};",
    "fetch(endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})",
    ".then(function(r){return r.json().then(function(j){return {status:r.status,json:j};},function(){return {status:r.status,json:{}};});})",
    ".then(function(res){",
    "if(res.status!==200){b.disabled=false;",
    "e.textContent=res.status===429?'Too many attempts. Try again shortly.':(res.status===401||res.status===400?'Sign-in failed. Check your credentials.':'Sign-in is unavailable. Try again later.');return;}",
    "return fetch(A,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({oauth_query:Q,postLogin:true})})",
    ".then(function(r2){return r2.json().then(function(j2){return {status:r2.status,json:j2};},function(){return {status:r2.status,json:{}};});})",
    ".then(function(up){",
    "var target=up.json.redirectURI||up.json.url;",
    "if(up.status>=200&&up.status<400&&target){location.href=target;return;}",
    "if(up.json.consentPage||up.json.consent){location.href=up.json.consentPage||up.json.consent;return;}",
    "location.reload();",
    "})",
    ".catch(function(){b.disabled=false;e.textContent='Sign-in is unavailable. Try again later.';});",
    "});",
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
