/**
 * WorkPass authorization-code + PKCE round trip, run by the Worker as a
 * backend-for-frontend so no token ever reaches browser JavaScript.
 *
 *   GET /auth/login          -> sets a short-lived HttpOnly PKCE cookie and sends
 *                               the browser to the authorization endpoint
 *   GET /oauth2/v1/authorize -> the public authorization endpoint URL; served by
 *                               the same provider as /api/auth/oauth2/authorize
 *   GET /enduser/callback    -> verifies state, redeems the code server-side, checks
 *                          that the ID token belongs to the signed-in session,
 *                          then returns the user to the portal
 *
 * The code is redeemed only to prove the flow completed for this user. The
 * tokens are discarded; the portal itself authenticates with the HttpOnly
 * session cookie, which is also what /api/* requires.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { createAuth } from "./config";
import { insertAuditEvent } from "../audit/store";
import { auditAuthRequest } from "../audit/auth-middleware";
import { rebuildRequest } from "./routes";
import { WORKPASS_CALLBACK_PATH, WORKPASS_SCOPES, workpassClientId, workpassRedirectUri } from "./workpass";

export const workpassRoutes = new Hono<{ Bindings: Env }>();

const COOKIE_NAME = "wp_oauth";
const COOKIE_MAX_AGE_SECONDS = 600;
const encoder = new TextEncoder();

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomToken(bytes = 32): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** Same-origin in-app path only; anything else collapses to the portal root. */
export function safePath(value: string | undefined): string {
  return value && value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\") && value.length <= 512
    ? value
    : "/";
}

function cookieAttributes(env: Env, maxAge: number): string {
  const secure = new URL(env.AUTH_BASE_URL).protocol === "https:" ? "; Secure" : "";
  return `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function readCookie(context: Context<{ Bindings: Env }>): { s: string; v: string; r: string } | null {
  const header = context.req.header("cookie") ?? "";
  const match = header.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE_NAME}=`));
  if (!match) return null;
  try {
    const padded = match.slice(COOKIE_NAME.length + 1).replace(/-/g, "+").replace(/_/g, "/");
    const parsed = JSON.parse(atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="))) as Record<string, unknown>;
    if (typeof parsed.s === "string" && typeof parsed.v === "string" && typeof parsed.r === "string") {
      return { s: parsed.s, v: parsed.v, r: parsed.r };
    }
  } catch {
    // Fall through: a malformed cookie is simply "no flow in progress".
  }
  return null;
}

function decodeJwtSubject(idToken: unknown): string | null {
  if (typeof idToken !== "string") return null;
  const payload = idToken.split(".")[1];
  if (!payload) return null;
  try {
    const padded = payload.replace(/-/g, "+").replace(/_/g, "/");
    const claims = JSON.parse(atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="))) as { sub?: unknown };
    return typeof claims.sub === "string" ? claims.sub : null;
  } catch {
    return null;
  }
}

async function audit(env: Env, userId: string | null, outcome: "success" | "failure", path: string): Promise<void> {
  try {
    await insertAuditEvent(env, {
      id: crypto.randomUUID(),
      actor_user_id: userId,
      target_user_id: userId,
      event_type: "authentication.workpass.login",
      outcome,
      request_path: path,
    });
  } catch {
    // The redirect outcome stands; the gap is visible in logs.
    console.error("WorkPass login audit event could not be recorded");
  }
}

workpassRoutes.get("/auth/login", async (context) => {
  const origin = new URL(context.env.AUTH_BASE_URL).origin;
  const state = randomToken(24);
  const verifier = randomToken(32);
  const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier))));
  const returnTo = safePath(context.req.query("redirect"));

  const fingerprintEventId = context.req.query("fingerprint_event_id");
  // Alphabetical, `%20`-separated scopes: the shape every OAuth2 client sends.
  const entries: Array<[string, string]> = [
    ["client_id", await workpassClientId(context.env)],
    ["code_challenge", challenge],
    ["code_challenge_method", "S256"],
    ["nonce", randomToken(24)],
    ["redirect_uri", workpassRedirectUri(context.env)],
    ["response_type", "code"],
    ["state", state],
    ["scope", ["openid", "profile", "email", ...WORKPASS_SCOPES].join(" ")],
  ];
  // Device-risk event for this authorization (single use; the login already
  // consumed its own). Ignored unless device assessment is on (server key set, no break-glass).
  if (fingerprintEventId && fingerprintEventId.length <= 256) entries.push(["fingerprint_event_id", fingerprintEventId]);
  const authorize = `${origin}/oauth2/v1/authorize?${entries
    .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
    .join("&")}`;

  const cookieValue = btoa(JSON.stringify({ s: state, v: verifier, r: returnTo }))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const headers = new Headers({
    Location: authorize,
    "Cache-Control": "no-store",
  });
  headers.append("Set-Cookie", `${COOKIE_NAME}=${cookieValue}; ${cookieAttributes(context.env, COOKIE_MAX_AGE_SECONDS)}`);
  return new Response(null, { status: 302, headers });
});

workpassRoutes.get("/oauth2/v1/authorize", (context) => {
  const target = new URL(context.req.url);
  target.pathname = "/api/auth/oauth2/authorize";
  return auditAuthRequest(rebuildRequest(context.req.raw, target, context.req.raw as unknown as RequestInit), context.env);
});

workpassRoutes.get(WORKPASS_CALLBACK_PATH, async (context) => {
  const origin = new URL(context.env.AUTH_BASE_URL).origin;
  const clear = `${COOKIE_NAME}=; ${cookieAttributes(context.env, 0)}`;
  const fail = async (userId: string | null) => {
    await audit(context.env, userId, "failure", WORKPASS_CALLBACK_PATH);
    const headers = new Headers({ Location: `${origin}/login?error=oauth`, "Cache-Control": "no-store" });
    headers.append("Set-Cookie", clear);
    return new Response(null, { status: 302, headers });
  };

  const flow = readCookie(context);
  const code = context.req.query("code");
  const state = context.req.query("state");
  if (!flow || !code || !state || state !== flow.s || code.length > 512) return fail(null);

  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers }).catch(() => null);
  if (!session) return fail(null);

  const tokenResponse = await auth.handler(new Request(`${origin}/api/auth/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: workpassRedirectUri(context.env),
      client_id: await workpassClientId(context.env),
      code_verifier: flow.v,
    }),
  })).catch(() => null);
  if (!tokenResponse?.ok) return fail(session.user.id);

  const tokens = await tokenResponse.json().catch(() => ({})) as { id_token?: unknown };
  // A code minted for someone else's session must never log this browser in.
  if (decodeJwtSubject(tokens.id_token) !== session.user.id) return fail(session.user.id);

  await audit(context.env, session.user.id, "success", WORKPASS_CALLBACK_PATH);
  const headers = new Headers({ Location: `${origin}${safePath(flow.r)}`, "Cache-Control": "no-store" });
  headers.append("Set-Cookie", clear);
  return new Response(null, { status: 302, headers });
});
