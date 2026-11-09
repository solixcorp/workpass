/**
 * Shared role-based authorization for cookie-authenticated administrator
 * surfaces. Every privileged route uses this single helper so the gating
 * cannot drift between modules: unauthenticated callers get 401, callers
 * without the platform admin role get 403, and state-changing requests must
 * arrive from the exact configured browser origin (ordinary same-origin GET
 * navigations carry no Origin header, so reads skip the origin check).
 */

import type { Context } from "hono";
import { createAuth } from "../auth/config";
import type { Env } from "../env";

/**
 * Guard an administrator surface. Returns the acting administrator's user ID,
 * or a rejection Response (401 unauthenticated, 403 role or origin) that the
 * caller returns immediately.
 */
export async function requireAdministrator(
  context: Context<{ Bindings: Env }>,
): Promise<{ userId: string } | Response> {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  const role = (session.user as typeof session.user & { role?: unknown }).role;
  if (typeof role !== "string" || !role.split(",").includes("admin")) {
    return Response.json({ error: "Forbidden" }, { status: 403 });
  }
  const mutating = context.req.method !== "GET";
  if (mutating && context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) {
    return Response.json({ error: "Invalid origin" }, { status: 403 });
  }
  return { userId: session.user.id };
}
