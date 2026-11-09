/**
 * SWA routes: the administrator application lifecycle and the user-triggered
 * grant authority. Applications never receive application credentials from
 * the IdP; grants are the signed-in user's own authorization to be signed in
 * automatically at a registered origin.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { requireAdministrator } from "../security/authorization";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import {
  evaluateAppAccess,
  hasRecentAppIssuance,
  loadAppAccessPolicy,
  policyTtlSeconds,
} from "../access/policies";
import { auditStandaloneOperation } from "../audit/store";
import { sessionSatisfiesRequireMfa } from "../mfa/second-factor";
import {
  consumeSwaGrant,
  createSwaApplication,
  getEnabledSwaApplicationByOrigin,
  getSwaApplication,
  issueSwaGrant,
  setSwaApplicationEnabled,
  validateSwaApplication,
} from "./applications";

export const SWA_PREFIX = "/api/swa";

const GENERIC_REJECTION = "The request cannot be processed";

export const swaAdminRoutes = new Hono<{ Bindings: Env }>();

swaAdminRoutes.get("/swa-applications", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const result = await context.env.DB.prepare(
    "SELECT id, name, origin, enabled FROM swa_applications ORDER BY id ASC LIMIT 200",
  ).all<{ id: string; name: string; origin: string; enabled: number }>();
  return context.json({
    applications: result.results.map((row) => ({ ...row, enabled: row.enabled === 1 })),
  });
});

swaAdminRoutes.post("/swa-applications", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  if (typeof value.name !== "string" || typeof value.origin !== "string") {
    return context.json({ error: "name and origin are required" }, 400);
  }
  const application = { id: crypto.randomUUID(), name: value.name, origin: value.origin };
  try { validateSwaApplication({ ...application, enabled: false }); } catch { return context.json({ error: "Invalid SWA application" }, 400); }
  return auditStandaloneOperation(context.env, "swa.application.create", "/api/admin/swa-applications", async () => {
    const inserted = await createSwaApplication(context.env, { ...application, createdBy: actor.userId });
    return {
      response: inserted
        ? Response.json({ application: { ...application, enabled: false } }, { status: 201 })
        : Response.json({ error: "An application with this origin already exists" }, { status: 409 }),
      actorUserId: actor.userId,
    };
  });
});

swaAdminRoutes.post("/swa-applications/:id/enable", async (context) => {
  return withApplication(context, "swa.application.enable", true);
});

swaAdminRoutes.post("/swa-applications/:id/disable", async (context) => {
  return withApplication(context, "swa.application.disable", false);
});

swaAdminRoutes.delete("/swa-applications/:id", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > 128) return context.json({ error: "Invalid application" }, 400);
  return auditStandaloneOperation(context.env, "swa.application.delete", context.req.path, async () => {
    const application = await getSwaApplication(context.env, id);
    if (!application) return { response: Response.json({ error: "Application not found" }, { status: 404 }), actorUserId: actor.userId };
    if (application.enabled) {
      return { response: Response.json({ error: "Disable the application before deleting it" }, { status: 409 }), actorUserId: actor.userId, targetUserId: id };
    }
    const removed = await context.env.DB.prepare(
      "DELETE FROM swa_applications WHERE id = ? AND enabled = 0",
    ).bind(id).run();
    return {
      response: removed.meta.changes === 1
        ? Response.json({ deleted: true })
        : Response.json({ error: "Application not found" }, { status: 404 }),
      actorUserId: actor.userId,
      targetUserId: id,
    };
  });
});

swaAdminRoutes.get("/swa-applications/:id/grants", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > 128) return context.json({ error: "Application not found" }, 404);
  const application = await getSwaApplication(context.env, id);
  if (!application) return context.json({ error: "Application not found" }, 404);
  const grants = await context.env.DB.prepare(
    `SELECT nonce, user_id AS userId, created_at AS createdAt, expires_at AS expiresAt,
            consumed_at IS NOT NULL AS consumed
     FROM swa_grants WHERE application_id = ? ORDER BY created_at DESC LIMIT 500`,
  ).bind(id).all<{ nonce: string; userId: string; createdAt: string; expiresAt: string; consumed: number }>();
  return context.json({
    grants: grants.results.map((grant) => ({ ...grant, nonce: `${grant.nonce.slice(0, 6)}…`, consumed: grant.consumed === 1 })),
  });
});

async function withApplication(
  context: Context<{ Bindings: Env }>,
  eventType: string,
  enabled: boolean,
): Promise<Response> {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > 128) return context.json({ error: "Invalid application" }, 400);
  const application = await getSwaApplication(context.env, id);
  if (!application) return context.json({ error: "Application not found" }, 404);
  return auditStandaloneOperation(context.env, eventType, context.req.path, async () => {
    const changed = await setSwaApplicationEnabled(context.env, id, enabled);
    return {
      response: changed
        ? Response.json({ application: { id: application.id, name: application.name, origin: application.origin, enabled } })
        : Response.json({ error: "Application not found" }, { status: 404 }),
      actorUserId: actor.userId,
      targetUserId: id,
    };
  });
}

export const swaUserRoutes = new Hono<{ Bindings: Env }>();

swaAdminRoutes.post("/swa-revocations", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const userId = typeof value.userId === "string" ? value.userId : "";
  if (userId.length === 0 || userId.length > 128) return context.json({ error: "Invalid body" }, 400);
  return auditStandaloneOperation(context.env, "swa.grants.revoked", "/api/admin/swa-revocations", async () => {
    const now = new Date().toISOString();
    const burned = await context.env.DB.prepare(
      "UPDATE swa_grants SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL AND expires_at > ?",
    ).bind(now, userId, now).run();
    return {
      response: Response.json({ revoked: burned.meta.changes }),
      actorUserId: actor.userId,
      targetUserId: userId,
    };
  });
});

swaUserRoutes.post("/api/swa/grants", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: GENERIC_REJECTION }, 403);
  }
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: GENERIC_REJECTION }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: GENERIC_REJECTION }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const origin = typeof value.origin === "string" ? value.origin : "";
  // Only the exact registered origin of an enabled application may grant.
  const application = await getEnabledSwaApplicationByOrigin(context.env, origin);
  if (!application) {
    console.error("SWA grant rejected", { stage: "unregistered-origin" });
    return context.json({ error: GENERIC_REJECTION }, 401);
  }
  // The per-application access policy gates grant issuance.
  const policySubject = `swa:${application.origin}`;
  const policy = await loadAppAccessPolicy(context.env, policySubject);
  if (policy) {
    // requireMfa honors session-bound proofs, not enrollment.
    if (policy.requireMfa && !(await sessionSatisfiesRequireMfa(context.env, session))) {
      console.error("SWA grant rejected", { stage: "mfa-required" });
      return context.json({ error: GENERIC_REJECTION }, 403);
    }
    const evaluation = await evaluateAppAccess(context.env, policy, session.user.id);
    if (!evaluation.allowed) {
      console.error("SWA grant rejected", { stage: "app-policy-denied" });
      return context.json({ error: GENERIC_REJECTION }, 403);
    }
    // Prior-success bypass: a recent attestation for this origin/user skips
    // the fresh-grant friction by allowing the exchange flow directly.
    if (await hasRecentAppIssuance(context.env, policySubject, session.user.id, policy.bypassWindowSeconds)) {
      console.error("SWA grant bypassed by prior success", { stage: "prior-success-bypass" });
    }
  }
  const grantTtl = policy && policy.sessionTtlSeconds !== null
    ? policyTtlSeconds(policy, 5 * 60)
    : 5 * 60;
  return auditStandaloneOperation(context.env, "swa.grant.issue", `${SWA_PREFIX}/grants`, async () => {
    const grant = await issueSwaGrant(context.env, {
      applicationId: application.id,
      userId: session.user.id,
      ttlSeconds: grantTtl,
    });
    if (policy) {
      await (await import("../access/policies")).recordAppIssuance(
        context.env,
        policySubject,
        session.user.id,
        "swa",
        policy.enforcementMode,
      );
    }
    return {
      response: Response.json(grant, { status: 201 }),
      actorUserId: session.user.id,
      targetUserId: application.id,
    };
  });
});

swaUserRoutes.post("/api/swa/exchange", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: GENERIC_REJECTION }, 403);
  }
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: GENERIC_REJECTION }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: GENERIC_REJECTION }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const nonce = typeof value.nonce === "string" ? value.nonce : "";
  if (nonce.length === 0 || nonce.length > 128) return context.json({ error: GENERIC_REJECTION }, 400);
  const consumed = await consumeSwaGrant(context.env, nonce);
  if (!consumed) {
    console.error("SWA exchange rejected", { stage: "invalid-or-replayed-nonce" });
    return context.json({ error: GENERIC_REJECTION }, 401);
  }
  if (consumed.userId !== session.user.id) {
    // A grant is only valid for its own acting user's session.
    console.error("SWA exchange rejected", { stage: "user-mismatch" });
    return context.json({ error: GENERIC_REJECTION }, 401);
  }
  const application = await getSwaApplication(context.env, consumed.applicationId);
  if (!application || !application.enabled) {
    console.error("SWA exchange rejected", { stage: "application-unavailable" });
    return context.json({ error: GENERIC_REJECTION }, 401);
  }
  return auditStandaloneOperation(context.env, "swa.grant.exchange", `${SWA_PREFIX}/exchange`, async () => ({
    response: Response.json({
      attestation: {
        application: { id: application.id, name: application.name, origin: application.origin },
        userId: session.user.id,
        expiresAt: consumed.expiresAt,
      },
    }),
    actorUserId: session.user.id,
    targetUserId: application.id,
  }));
});
