/**
 * Access-request API (docs/design/access-requests.md). The admin router mounts
 * under /api/admin (requireAdministrator) and manages rules, bindings, the
 * request list and revocation. The user router serves the Discover list
 * (requestable), request creation, My Requests, cancel, the reviewer queue
 * (reviews) and the review decision; mutations require the same browser origin
 * as other session-authenticated mutating surfaces.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { createAuth } from "../auth/config";
import { auditStandaloneOperation } from "../audit/store";
import {
  cancelAccessRequest,
  cleanupAccessRequests,
  createAccessRequest,
  createRequestBinding,
  createRequestRule,
  deleteRequestBinding,
  deleteRequestRule,
  listRequestsForUser,
  listRequestableForUser,
  listRequestBindings,
  listRequestRules,
  listReviewQueue,
  notifyAccessRequestEvent,
  SUBJECT_PATTERN,
  reviewAccessRequest,
  resolveRuleReviewers,
  revokeAccessRequest,
} from "./requests";

const GENERIC_REJECTION = "The request cannot be processed";

export const accessRequestAdminRoutes = new Hono<{ Bindings: Env }>();

accessRequestAdminRoutes.get("/access-request-rules", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  return context.json({ rules: await listRequestRules(context.env) });
});

accessRequestAdminRoutes.post("/access-request-rules", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  if (typeof value.name !== "string") return context.json({ error: "name is required" }, 400);
  return auditStandaloneOperation(context.env, "access.request_rule.create", "/api/admin/access-request-rules", async () => {
    try {
      const rule = await createRequestRule(context.env, value as { name: string }, admin.userId);
      return {
        response: Response.json({ rule }, { status: 201 }),
        actorUserId: admin.userId,
        targetUserId: rule.name,
      };
    } catch (error) {
      return {
        response: Response.json({ error: error instanceof Error ? error.message : "Invalid rule" }, { status: 400 }),
        actorUserId: admin.userId,
      };
    }
  });
});

accessRequestAdminRoutes.delete("/access-request-rules/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  return auditStandaloneOperation(context.env, "access.request_rule.delete", context.req.path, async () => {
    try {
      const removed = await deleteRequestRule(context.env, id);
      return {
        response: removed === 1 ? Response.json({ deleted: true }) : Response.json({ error: "Rule not found or still bound" }, { status: 404 }),
        actorUserId: admin.userId,
        targetUserId: id,
      };
    } catch (error) {
      return {
        response: Response.json({ error: error instanceof Error ? error.message : "Delete failed" }, { status: 409 }),
        actorUserId: admin.userId,
      };
    }
  });
});

accessRequestAdminRoutes.get("/access-request-bindings", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  return context.json({ bindings: await listRequestBindings(context.env) });
});

accessRequestAdminRoutes.post("/access-request-bindings", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  if (typeof value.subject !== "string" || typeof value.ruleId !== "string") {
    return context.json({ error: "subject and ruleId are required" }, 400);
  }
  return auditStandaloneOperation(context.env, "access.request_binding.create", "/api/admin/access-request-bindings", async () => {
    try {
      const binding = await createRequestBinding(context.env, value as { subject: string; ruleId: string }, admin.userId);
      return {
        response: Response.json({ binding }, { status: 201 }),
        actorUserId: admin.userId,
        targetUserId: binding.subject,
      };
    } catch (error) {
      return {
        response: Response.json({ error: error instanceof Error ? error.message : "Invalid binding" }, { status: 400 }),
        actorUserId: admin.userId,
      };
    }
  });
});

accessRequestAdminRoutes.delete("/access-request-bindings/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  return auditStandaloneOperation(context.env, "access.request_binding.delete", context.req.path, async () => {
    const removed = await deleteRequestBinding(context.env, id);
    return {
      response: removed === 1 ? Response.json({ deleted: true }) : Response.json({ error: "Binding not found" }, { status: 404 }),
      actorUserId: admin.userId,
      targetUserId: id,
    };
  });
});

accessRequestAdminRoutes.get("/access-requests", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const status = context.req.query("status");
  // Parameterize the status filter; the column constraint list is checked in the schema.
  if (status !== undefined && !/^[a-z_]{1,20}$/.test(status)) {
    return context.json({ error: "Invalid status filter" }, 400);
  }
  const rows = await context.env.DB.prepare(
    `SELECT id, subject, user_id AS userId, justification, status, requested_expiry_seconds AS requestedExpirySeconds,
            granted_expires_at AS grantedExpiresAt, pending_expires_at AS pendingExpiresAt,
            decided_at AS decidedAt, decided_by AS decidedBy, decision_note AS decisionNote, created_at AS createdAt
     FROM access_requests ${status ? "WHERE status = ?" : ""} ORDER BY created_at DESC LIMIT 500`,
  ).bind(...(status ? [status] : [])).all();
  return context.json({ requests: rows.results });
});

accessRequestAdminRoutes.post("/access-requests/:id/revoke", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  const revoked = await revokeAccessRequest(context.env, id, admin.userId);
  return revoked ? context.json({ revoked: true }) : context.json({ error: "No active grant for this request" }, { status: 404 });
});

export const accessRequestUserRoutes = new Hono<{ Bindings: Env }>();

const USER_PREFIX = "/api/access-requests";

async function requireSession(context: { env: Env; req: { raw: { headers: Headers } } }): Promise<{ userId: string } | Response> {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return Response.json({ error: GENERIC_REJECTION }, { status: 401 });
  return { userId: session.user.id };
}

function requireMutatingOrigin(context: { env: Env; req: { header: (name: string) => string | undefined } }): Response | null {
  const origin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== origin) return Response.json({ error: GENERIC_REJECTION }, { status: 403 });
  return null;
}

/** Discover: the applications this user may request access to. */
accessRequestUserRoutes.get(`${USER_PREFIX}/requestable`, async (context) => {
  const actor = await requireSession(context);
  if (actor instanceof Response) return actor;
  return context.json({ requestable: await listRequestableForUser(context.env, actor.userId) });
});

/** My Requests: everything this user has requested. */
accessRequestUserRoutes.get(`${USER_PREFIX}/me`, async (context) => {
  const actor = await requireSession(context);
  if (actor instanceof Response) return actor;
  return context.json({ requests: await listRequestsForUser(context.env, actor.userId) });
});

/** Create an access request with its justification. */
accessRequestUserRoutes.post(USER_PREFIX, async (context) => {
  const originFailure = requireMutatingOrigin(context);
  if (originFailure) return originFailure;
  const actor = await requireSession(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: GENERIC_REJECTION }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: GENERIC_REJECTION }, 400);
  const value = body as Record<string, unknown>;
  const subject = typeof value.subject === "string" ? value.subject : "";
  const justification = typeof value.justification === "string" ? value.justification : "";
  if (!SUBJECT_PATTERN.test(subject)) {
    return context.json({ error: GENERIC_REJECTION }, 400);
  }
  let request;
  try {
    request = await createAccessRequest(context.env, { subject, userId: actor.userId, justification, requestedExpirySeconds: value.requestedExpirySeconds });
  } catch (error) {
    console.warn("Access request rejected", {
      stage: "create",
      name: error instanceof Error ? error.name : "UnknownError",
    });
    return context.json({ error: GENERIC_REJECTION }, 400);
  }
  const bindingRule = await context.env.DB.prepare(
    `SELECT r.id AS ruleId, r.min_reviewers AS minReviewers, r.notify_mode AS notifyMode
     FROM request_rule_bindings b JOIN request_rules r ON r.id = b.rule_id WHERE b.id = ?`,
  ).bind(request.bindingId).first<{ ruleId: string; minReviewers: number; notifyMode: string }>();
  if (bindingRule) {
    const reviewers = await resolveRuleReviewers(context.env, bindingRule.ruleId, bindingRule.minReviewers, bindingRule.notifyMode);
    // Best-effort; never authoritative for the reviewer queue.
    await notifyAccessRequestEvent(context.env, {
      type: "access_request.created",
      requestId: request.id,
      subject: request.subject,
      requesterId: request.userId,
      justification: request.justification,
      reviewers,
    });
  }
  return context.json({ request }, { status: 201 });
});

/** Cancel the caller's own pending request. */
accessRequestUserRoutes.post(`${USER_PREFIX}/:id/cancel`, async (context) => {
  const originFailure = requireMutatingOrigin(context);
  if (originFailure) return originFailure;
  const actor = await requireSession(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  const cancelled = await cancelAccessRequest(context.env, id, actor.userId);
  return cancelled ? context.json({ cancelled: true }) : context.json({ error: GENERIC_REJECTION }, 404);
});

/** For My Review: the pending requests this user may review. */
accessRequestUserRoutes.get(`${USER_PREFIX}/reviews`, async (context) => {
  const actor = await requireSession(context);
  if (actor instanceof Response) return actor;
  return context.json({ pending: await listReviewQueue(context.env, actor.userId) });
});

/** Approve or deny a request; a requester can never review their own request. */
accessRequestUserRoutes.post(`${USER_PREFIX}/:id/review`, async (context) => {
  const originFailure = requireMutatingOrigin(context);
  if (originFailure) return originFailure;
  const actor = await requireSession(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: GENERIC_REJECTION }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: GENERIC_REJECTION }, 400);
  const value = body as Record<string, unknown>;
  const decision = value.decision === "approved" ? "approved" : value.decision === "denied" ? "denied" : null;
  if (decision === null) return context.json({ error: GENERIC_REJECTION }, 400);
  const id = context.req.param("id");
  let outcome;
  try {
    outcome = await reviewAccessRequest(context.env, {
      requestId: id,
      reviewerId: actor.userId,
      decision,
      note: typeof value.note === "string" ? value.note : undefined,
    });
  } catch (error) {
    console.warn("Access review rejected", {
      stage: "review",
      reason: error instanceof Error ? error.message : "UnknownError",
    });
    return context.json({ error: GENERIC_REJECTION }, 403);
  }
  if (!outcome) return context.json({ error: GENERIC_REJECTION }, 404);
  if (outcome.newStatus !== null) {
    // Best-effort; the audit event is written by the engine.
    await notifyAccessRequestEvent(context.env, {
      type: decision === "approved" ? "access_request.approved" : "access_request.denied",
      requestId: id,
      subject: outcome.request.subject,
      requesterId: outcome.request.userId,
      justification: outcome.request.justification,
      decision: { reviewerId: actor.userId, decision, note: outcome.request.decisionNote, newStatus: outcome.newStatus },
    });
  }
  return context.json({ request: outcome.request, statusApplied: outcome.newStatus });
});
