/**
 * Administrator routes for the application access-policy engine: policy
 * definitions, group bindings and the per-subject issuance activity view.
 */

import { Hono } from "hono";
import { requireAdministrator } from "../security/authorization";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import { loadAppAccessPolicy, upsertAppAccessPolicy } from "./policies";

export const accessPolicyRoutes = new Hono<{ Bindings: Env }>();

accessPolicyRoutes.get("/app-access-policies", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const rows = await context.env.DB.prepare(
    `SELECT subject, allowed_methods AS allowedMethods, session_ttl_seconds AS sessionTtlSeconds,
            bypass_window_seconds AS bypassWindowSeconds, enforcement_mode AS enforcementMode,
            updated_at AS updatedAt
     FROM app_access_policies ORDER BY subject ASC LIMIT 200`,
  ).all<{ subject: string; allowedMethods: string; sessionTtlSeconds: number | null; bypassWindowSeconds: number; enforcementMode: string; updatedAt: string }>();
  const policies = [];
  for (const row of rows.results) {
    const groups = await context.env.DB.prepare(
      "SELECT group_id FROM app_policy_groups WHERE subject = ?",
    ).bind(row.subject).all<{ group_id: string }>();
    policies.push({
      ...row,
      groups: groups.results.map((g) => g.group_id),
      enforcementMode: row.enforcementMode,
    });
  }
  return context.json({ policies });
});

accessPolicyRoutes.put("/app-access-policies", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const subject = typeof value.subject === "string" ? value.subject : "";
  const allowedMethods = typeof value.allowedMethods === "string" ? value.allowedMethods : "password,passkey";
  const sessionTtlSeconds = typeof value.sessionTtlSeconds === "number" ? value.sessionTtlSeconds : null;
  const bypassWindowSeconds = typeof value.bypassWindowSeconds === "number" ? value.bypassWindowSeconds : 28800;
  const enforcementMode = value.enforcementMode === "observe" ? "observe" : "enforce";
  const groups = Array.isArray(value.groups) ? value.groups.filter((g): g is string => typeof g === "string" && g.length <= 128) : [];
  const subjectPattern = /^(saml|oidc|wsfed|swa):[A-Za-z0-9_.:\/-]{1,2000}$/;
  if (!subjectPattern.test(subject)) {
    return context.json({ error: 'subject must be "saml:<entityId>", "oidc:<clientId>", "wsfed:<realm>" or "swa:<origin>"' }, 400);
  }
  const { upsertAppAccessPolicy } = await import("./policies");
  const policy = {
    subject,
    allowedMethods,
    sessionTtlSeconds,
    bypassWindowSeconds,
    enforcementMode: enforcementMode as "enforce" | "observe",
    groups,
  };
  try {
    await upsertAppAccessPolicy(context.env, policy, admin.userId);
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "Invalid policy" }, 400);
  }
  return auditStandaloneOperation(context.env, "access.policy.update", "/api/admin/app-access-policies", async () => ({
    response: Response.json({ policy }),
    actorUserId: admin.userId,
    targetUserId: subject,
  }));
});

accessPolicyRoutes.delete("/app-access-policies/{subject}", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const subject = context.req.param("subject");
  if (!subject || subject.length > 2020) return context.json({ error: "Invalid policy" }, 404);
  const existing = await loadAppAccessPolicy(context.env, decodeURIComponent(subject));
  if (!existing) return context.json({ error: "Policy not found" }, 404);
  return auditStandaloneOperation(context.env, "access.policy.delete", context.req.path, async () => {
    let removed = 0;
    try {
      const result = await context.env.DB.prepare("DELETE FROM app_access_policies WHERE subject = ?").bind(existing.subject).run();
      removed = result.meta.changes;
      await context.env.DB.prepare("DELETE FROM app_policy_groups WHERE subject = ?").bind(existing.subject).run();
    } catch {
      removed = 0;
    }
    return {
      response: removed === 1 ? Response.json({ deleted: true }) : Response.json({ error: "Policy not found" }, { status: 404 }),
      actorUserId: admin.userId,
      targetUserId: existing.subject,
    };
  });
});

/** The issuance activity for one subject (admin; visibility + review). */
accessPolicyRoutes.get("/app-access-policies/{subject}/activity", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const subjectRaw = context.req.param("subject") ?? "";
  const subject = decodeURIComponent(subjectRaw);
  const rows = await context.env.DB.prepare(
    `SELECT user_id AS userId, issued_at AS issuedAt, enforcement_mode AS enforcementMode, method
     FROM app_issuance_history WHERE subject = ? ORDER BY issued_at DESC LIMIT 500`,
  ).bind(subject).all<{ userId: string; issuedAt: string; enforcementMode: string; method: string | null }>();
  return context.json({ subject, activity: rows.results });
});
