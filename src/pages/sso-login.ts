/**
 * Handoff for protocol requests (SAML, WS-Federation, OAuth 1.0a) that reach
 * the IdP without a session. The browser is sent to the WorkPass sign-in with
 * the verified request URL as the return target; after sign-in the same URL is
 * requested again, so the protocol's signature, validation and one-time claim
 * checks all run again on the authenticated round. The target is a same-origin
 * path only, so this cannot be turned into an open redirect.
 */

import type { Context } from "hono";
import type { Env } from "../env";
import { safePath } from "../auth/workpass-routes";

export function redirectToSignIn(context: Context<{ Bindings: Env }>): Response {
  const request = new URL(context.req.url);
  const origin = new URL(context.env.AUTH_BASE_URL).origin;
  const target = safePath(`${request.pathname}${request.search}`);
  const login = new URL("/auth/login", origin);
  login.searchParams.set("redirect", target);
  return new Response(null, {
    status: 302,
    headers: {
      Location: login.toString(),
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}
