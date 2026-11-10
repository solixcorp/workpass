/**
 * Administrator routes for the per-application claim release policy. The
 * global flags decide whether released claims are possible at all; a policy
 * row for one subject decides which kinds that application receives (an AND
 * with the flags). Authorization mirrors the other admin routes
 * (administrator session plus exact configured origin); writes are audited.
 */

import { Hono } from "hono";
import { requireAdministrator } from "../security/authorization";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import {
  deleteClaimReleasePolicy,
  getClaimReleasePolicy,
  listClaimReleasePolicies,
  upsertClaimReleasePolicy,
} from "./release-policy";

export const claimReleasePolicyRoutes = new Hono<{ Bindings: Env }>();

claimReleasePolicyRoutes.use("/claim-release-policies*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

claimReleasePolicyRoutes.get("/claim-release-policies", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  return context.json({ policies: await listClaimReleasePolicies(context.env) });
});

claimReleasePolicyRoutes.put("/claim-release-policies/:encodedSubject", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const subject = decodeURIComponent(context.req.param("encodedSubject") ?? "");
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  // Absent keys default to allowed: a policy row selects a subset of the
  // flag-permitted kinds, never beyond them.
  const policy = {
    subject,
    allowAccountClaims: value.allowAccountClaims === undefined ? true : value.allowAccountClaims === true,
    allowUserAttributes: value.allowUserAttributes === undefined ? true : value.allowUserAttributes === true,
    attributeAllowlist: value.attributeAllowlist === undefined ? undefined
      : value.attributeAllowlist === null ? null
      : Array.isArray(value.attributeAllowlist) ? (value.attributeAllowlist as string[]) : undefined,
  };
  if (value.attributeAllowlist !== undefined && value.attributeAllowlist !== null && !Array.isArray(value.attributeAllowlist)) {
    return context.json({ error: "attributeAllowlist must be an array of keys or null" }, 400);
  }
  return auditStandaloneOperation(context.env, "claim.policy.update", "/api/admin/claim-release-policies", async () => {
    try {
      await upsertClaimReleasePolicy(context.env, policy, actor.userId);
    } catch (error) {
      return {
        response: Response.json(
          { error: error instanceof Error ? error.message : "Invalid policy" },
          { status: 400 },
        ),
        actorUserId: actor.userId,
      };
    }
    return {
      response: Response.json({ policy }),
      actorUserId: actor.userId,
      targetUserId: policy.subject,
    };
  });
});

claimReleasePolicyRoutes.get("/claim-release-policies/:encodedSubject", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const subject = decodeURIComponent(context.req.param("encodedSubject") ?? "");
  const policy = await getClaimReleasePolicy(context.env, subject);
  if (!policy) return context.json({ error: "Policy not found" }, 404);
  return context.json({ policy });
});

claimReleasePolicyRoutes.delete("/claim-release-policies/:encodedSubject", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const subject = decodeURIComponent(context.req.param("encodedSubject") ?? "");
  return auditStandaloneOperation(context.env, "claim.policy.delete", context.req.path, async () => {
    const removed = await deleteClaimReleasePolicy(context.env, subject);
    if (!removed) {
      return { response: Response.json({ error: "Policy not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    return {
      response: Response.json({ deleted: true }),
      actorUserId: actor.userId,
      targetUserId: subject,
    };
  });
});
