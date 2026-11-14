/**
 * OIDC login handoff: the authorization endpoint redirects unauthenticated
 * users here with a signed query. The query's signature and expiry are
 * verified, then the browser continues to the SPA sign-in screen with the
 * signed query carried as one opaque `oq` value. After sign-in the SPA posts
 * it back to /oauth2/continue, which re-verifies the signature, so nothing
 * here can be forged or swapped.
 */

import { Hono } from "hono";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { signInBrandForClient } from "../applications/sign-in-brand";

export const oidcSignInRoutes = new Hono<{ Bindings: Env }>();

oidcSignInRoutes.get("/sign-in", async (context) => {
  const oauthQuery = new URL(context.req.url).searchParams.toString();
  const params = new URLSearchParams(oauthQuery);
  if (
    oauthQuery.length === 0 ||
    oauthQuery.length > 16384 ||
    !params.get("client_id") ||
    !(await verifyOAuthQueryParams(oauthQuery, context.env.AUTH_SECRET))
  ) {
    // A bare or tampered /sign-in visit is not a startable flow: the
    // authorization endpoint must originate it.
    return context.json({ error: "Sign-in must be started by an application" }, 400);
  }
  const origin = new URL(context.env.AUTH_BASE_URL).origin;
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${origin}/login?${new URLSearchParams({ oq: oauthQuery }).toString()}`,
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
});

/**
 * Which application is asking, for the sign-in card. Only a request whose
 * signature verifies is answered, so a client id alone reveals nothing.
 */
oidcSignInRoutes.post("/api/config/login/app", async (context) => {
  const body = (await context.req.json().catch(() => null)) as { oq?: unknown } | null;
  const oauthQuery = typeof body?.oq === "string" ? body.oq : "";
  context.header("Cache-Control", "no-store");
  if (!oauthQuery || oauthQuery.length > 16384) return context.json({ app: null });
  const verified = await verifyOAuthQueryParams(oauthQuery, context.env.AUTH_SECRET).catch(() => false);
  const clientId = new URLSearchParams(oauthQuery).get("client_id");
  if (!verified || !clientId) return context.json({ app: null });
  return context.json({ app: await signInBrandForClient(context.env, clientId) });
});
