/**
 * OIDC consent. The authorization endpoint redirects authenticated users to
 * /consent (served by the single-page app) with a tamper-proofed, signed oauth
 * query. This module answers what the page needs to show: who is asking for
 * what, and whether this person may open the app at all. Approving sends the
 * signed query back to the native consent endpoint, which verifies the
 * signature, so parameters cannot be forged or swapped by the page or the user.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { evaluateAppAccess, hasRecentAppIssuance, loadAppAccessPolicy } from "../access/policies";

export const consentRoutes = new Hono<{ Bindings: Env }>();

consentRoutes.get("/api/consent/context", async (context) => {
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "unauthorized" }, 401);
  const query = new URL(context.req.url).searchParams;
  const clientId = query.get("client_id") ?? "";
  if (!clientId || clientId.length > 200) return context.json({ error: "The single sign-on request cannot be processed" }, 400);
  const scopes = (query.get("scope") ?? "").split(" ").filter(Boolean).slice(0, 32);

  // The per-application access policy: group gating at the consent step.
  const subject = `oidc:${clientId}`;
  let allowed = true;
  try {
    const policy = await loadAppAccessPolicy(context.env, subject);
    if (policy) {
      const evaluation = await evaluateAppAccess(context.env, policy, session.user.id);
      await hasRecentAppIssuance(context.env, subject, session.user.id, policy.bypassWindowSeconds);
      allowed = evaluation.allowed;
    }
  } catch {
    return context.json({ error: "Authorization policy unavailable" }, 503);
  }

  const app = await context.env.DB.prepare(
    "SELECT slug, name, description, icon_key AS iconKey, icon_url AS iconUrl FROM applications WHERE protocol = 'oidc' AND binding = ?",
  ).bind(clientId).first<{ slug: string; name: string; description: string | null; iconKey: string | null; iconUrl: string | null }>().catch(() => null);
  return context.json({
    allowed,
    application: {
      name: app?.name ?? clientId,
      description: app?.description ?? null,
      icon: app ? (app.iconKey ? `/application/${app.slug}/icon` : app.iconUrl) : null,
    },
    scopes,
    account: { name: session.user.name, email: session.user.email },
  });
});
