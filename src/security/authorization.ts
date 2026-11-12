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
import { getStepUpChallenge } from "./step-up";
import { getSessionMfaProof, type MfaCheckedSession } from "../mfa/second-factor";
import { userMustUseMfa } from "../mfa/policy";
import { LEGACY_WORKPASS_CLIENT_ID } from "../auth/workpass";

export function requireSameOrigin(context: Context<{ Bindings: Env }>): Response | null {
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) {
    return Response.json({ error: "Invalid origin" }, { status: 403 });
  }
  return null;
}

export async function administratorMfaAllowed(env: Env, session: MfaCheckedSession & { user: { id: string; role?: unknown } }): Promise<boolean> {
  const token = session.session?.token;
  if (typeof token !== "string" || !token || token.length > 512) return false;
  try {
    const challenge = await getStepUpChallenge(env, token, true);
    if (challenge.state === "pending" || challenge.state === "expired") return false;
    const proof = await getSessionMfaProof(env, token, true);
    if (proof?.userId === session.user.id && proof.methods.some((method) => method !== "passkey")) return true;
    const id = await env.DB.prepare("SELECT value FROM app_settings WHERE key = ?")
      .bind("workpass.client_id").first<{ value: string }>();
    const policy = await env.DB.prepare("SELECT require_mfa FROM app_access_policies WHERE subject = ?")
      .bind(`oidc:${id?.value ?? LEGACY_WORKPASS_CLIENT_ID}`).first<{ require_mfa: number }>();
    return !userMustUseMfa(env, session.user) && policy?.require_mfa !== 1;
  } catch {
    return false;
  }
}

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
  if (!await administratorMfaAllowed(context.env, session)) {
    return Response.json({ error: "Additional verification is required" }, { status: 403 });
  }
  const mutating = context.req.method !== "GET";
  if (mutating) {
    const rejection = requireSameOrigin(context);
    if (rejection) return rejection;
  }
  return { userId: session.user.id };
}
