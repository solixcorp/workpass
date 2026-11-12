/**
 * Policy and binding management API (docs/design/authentik-policies.md).
 * Admin-gated like every other privileged surface; mutations audited.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import type { BindingTarget } from "../policies/types";
import { auditStandaloneOperation } from "../audit/store";
import { implementedTypes, validatePolicyConfig } from "../policies/registry";
import { loadAppAccessPolicy } from "../access/policies";

const TARGET_PATTERN = /^(application|login|password_entry|user_write|notification_rule)$/;
const SUBJECT_PATTERN = /^(saml|oidc|wsfed|swa):[A-Za-z0-9_.:\/-]{1,2000}$/;

export const policyRoutes = new Hono<{ Bindings: Env }>();

policyRoutes.get("/policies", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const rows = await context.env.DB.prepare(
    `SELECT id, name, type, config, enabled, execution_logging AS executionLogging, created_at AS createdAt
     FROM policies ORDER BY name ASC LIMIT 200`,
  ).all<Record<string, unknown>>();
  return context.json({
    policies: rows.results.map((row) => ({
      ...row,
      config: JSON.parse((row.config as string) ?? "{}") as unknown,
      enabled: row.enabled === 1,
      executionLogging: row.executionLogging === 1,
    })),
    implementedTypes: implementedTypes(),
  });
});

policyRoutes.post("/policies", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  const name = typeof value.name === "string" ? value.name.trim() : "";
  const type = typeof value.type === "string" ? value.type : "";
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) {
    return context.json({ error: "name must be 1-64 characters from [A-Za-z0-9_.-]" }, 400);
  }
  if (!implementedTypes().includes(type)) {
    return context.json({ error: `unsupported policy type ${type}; supported: ${implementedTypes().join(", ")}` }, 400);
  }
  let config: unknown;
  try {
    config = validatePolicyConfig(type, value.config ?? {}).config;
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "Invalid config" }, 400);
  }
  const enabled = value.enabled === undefined ? true : value.enabled === true;
  const executionLogging = value.executionLogging === true;
  return auditStandaloneOperation(context.env, "policy.create", "/api/admin/policies", async () => {
    const duplicate = await context.env.DB.prepare("SELECT id FROM policies WHERE name = ?").bind(name).first();
    if (duplicate) {
      return { response: Response.json({ error: "A policy with that name exists" }, { status: 409 }), actorUserId: admin.userId };
    }
    const id = crypto.randomUUID();
    await context.env.DB.prepare(
      `INSERT INTO policies (id, name, type, config, enabled, execution_logging, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, name, type, JSON.stringify(config), enabled ? 1 : 0, executionLogging ? 1 : 0, admin.userId, new Date().toISOString()).run();
    return {
      response: Response.json({ policy: { id, name, type, config, enabled, executionLogging } }, { status: 201 }),
      actorUserId: admin.userId,
      targetUserId: name,
    };
  });
});

policyRoutes.put("/policies/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const row = await context.env.DB.prepare("SELECT id, name, type, config FROM policies WHERE id = ?").bind(id)
    .first<{ id: string; name: string; type: string; config: string }>();
  if (!row) return context.json({ error: "Policy not found" }, 404);
  return auditStandaloneOperation(context.env, "policy.update", context.req.path, async () => {
    let config: unknown;
    try {
      config = validatePolicyConfig(row.type, value.config ?? JSON.parse(row.config)).config;
    } catch (error) {
      return { response: Response.json({ error: error instanceof Error ? error.message : "Invalid config" }, { status: 400 }), actorUserId: admin.userId };
    }
    const enabled = value.enabled === undefined ? undefined : value.enabled === true ? 1 : 0;
    const executionLogging = value.executionLogging === undefined ? undefined : value.executionLogging === true ? 1 : 0;
    await context.env.DB.prepare(
      `UPDATE policies SET config = ?, enabled = COALESCE(?, enabled), execution_logging = COALESCE(?, execution_logging) WHERE id = ?`,
    ).bind(JSON.stringify(config), enabled ?? null, executionLogging ?? null, id).run();
    const updated = await context.env.DB.prepare("SELECT config, enabled, execution_logging AS executionLogging FROM policies WHERE id = ?")
      .bind(id).first<Record<string, unknown>>();
    return {
      response: Response.json({
        policy: { id, name: row.name, type: row.type, config: JSON.parse((updated?.config as string) ?? "{}"),
          enabled: updated?.enabled === 1, executionLogging: updated?.executionLogging === 1 },
      }),
      actorUserId: admin.userId,
      targetUserId: row.name,
    };
  });
});

policyRoutes.delete("/policies/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  return auditStandaloneOperation(context.env, "policy.delete", context.req.path, async () => {
    const bound = await context.env.DB.prepare(
      "SELECT COUNT(*) AS count FROM policy_bindings WHERE policy_id = ?",
    ).bind(id).first<{ count: number }>();
    if ((bound?.count ?? 0) > 0) {
      return { response: Response.json({ error: "The policy is still bound; unbind it first" }, { status: 409 }), actorUserId: admin.userId };
    }
    const removed = await context.env.DB.prepare("DELETE FROM policies WHERE id = ?").bind(id).run();
    return {
      response: removed.meta.changes === 1 ? Response.json({ deleted: true }) : Response.json({ error: "Policy not found" }, { status: 404 }),
      actorUserId: admin.userId,
      targetUserId: id,
    };
  });
});

// --- bindings ---------------------------------------------------------------

policyRoutes.get("/policy-bindings", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const target = context.req.query("target");
  const targetRef = context.req.query("targetRef");
  if (target !== null && target !== undefined && !TARGET_PATTERN.test(target)) {
    return context.json({ error: "Invalid target" }, 400);
  }
  const rows = await context.env.DB.prepare(
    `SELECT b.id, b.target, b.target_ref AS targetRef, b.policy_id AS policyId,
            b.bind_user_id AS bindUserId, b.bind_group_id AS bindGroupId,
            b.order_index AS orderIndex, b.mode, b.negate, b.failure_result AS failureResult,
            b.enabled, b.created_at AS createdAt,
            p.name AS policyName, p.type AS policyType
     FROM policy_bindings b LEFT JOIN policies p ON p.id = b.policy_id
     ${target ? "WHERE b.target = ? AND b.target_ref = ?" : ""}
     ORDER BY b.target ASC, b.target_ref ASC, b.order_index ASC, b.id ASC
     LIMIT 300`,
  ).bind(...(target ? [target, targetRef ?? ""] : [])).all<Record<string, unknown>>();
  return context.json({
    bindings: rows.results.map((row) => ({
      ...row,
      negate: row.negate === 1,
      enabled: row.enabled === 1,
    })),
  });
});

policyRoutes.post("/policy-bindings", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  const target = typeof value.target === "string" ? value.target : "";
  if (value.targetRef !== undefined && typeof value.targetRef !== "string") {
    return context.json({ error: "targetRef must be a string" }, 400);
  }
  let targetRef = typeof value.targetRef === "string" ? value.targetRef : "";
  if (!TARGET_PATTERN.test(target)) {
    return context.json({ error: "target must be application, login, password_entry, user_write or notification_rule" }, 400);
  }
  if (target === "application") {
    // Bindings resolve against the application access-policy namespace; the
    // subject must be an existing registered app or an existing policy subject.
    targetRef = targetRef.toLowerCase();
    const subjectPattern = SUBJECT_PATTERN.test(targetRef);
    const policySubject = subjectPattern ? await loadAppAccessPolicy(context.env, targetRef) : null;
    const swaApp = targetRef.startsWith("swa:")
      ? await context.env.DB.prepare("SELECT id FROM swa_applications WHERE origin = ?").bind(targetRef.slice(4)).first()
      : null;
    const samlSp = targetRef.startsWith("saml:")
      ? await context.env.DB.prepare("SELECT id FROM saml_service_providers WHERE entity_id = ?").bind(targetRef.slice(5)).first()
      : null;
    const wsfedRp = targetRef.startsWith("wsfed:")
      ? await context.env.DB.prepare("SELECT id FROM wsfed_relying_parties WHERE realm = ?").bind(targetRef.slice(6)).first()
      : null;
    if (!policySubject && !swaApp && !samlSp && !wsfedRp) {
      return context.json({ error: "targetRef must be a registered application subject or an existing policy subject" }, 400);
    }
  } else if (target === "login" || target === "password_entry") {
    // These are global surfaces; omission and the empty string are equivalent.
    if (targetRef !== "") return context.json({ error: "targetRef must be empty for global targets" }, 400);
  } else if (targetRef.length === 0 || targetRef.length > 128) {
    return context.json({ error: "targetRef is required" }, 400);
  }
  const policyId = typeof value.policyId === "string" && value.policyId ? value.policyId : null;
  const bindUserId = typeof value.bindUserId === "string" && value.bindUserId ? value.bindUserId : null;
  const bindGroupId = typeof value.bindGroupId === "string" && value.bindGroupId ? value.bindGroupId : null;
  const selectors = [policyId, bindUserId, bindGroupId].filter((entry) => entry !== null);
  if (selectors.length !== 1) {
    return context.json({ error: "exactly one of policyId, bindUserId or bindGroupId is required" }, 400);
  }
  if (bindGroupId) {
    const group = await context.env.DB.prepare("SELECT id FROM directory_groups WHERE id = ?").bind(bindGroupId).first();
    if (!group) return context.json({ error: "Unknown group" }, 404);
  }
  if (bindUserId) {
    const user = await context.env.DB.prepare('SELECT id FROM "user" WHERE id = ?').bind(bindUserId).first();
    if (!user) return context.json({ error: "Unknown user" }, 404);
  }
  const orderIndex = typeof value.order === "number" && Number.isInteger(value.order) && value.order >= 0 && value.order <= 999
    ? value.order : 0;
  const mode = value.mode === "any" ? "any" : "all";
  const negate = value.negate === true;
  const failureResult = value.failureResult === "pass" ? "pass" : "fail";
  const enabled = value.enabled === undefined ? true : value.enabled === true;
  if (policyId) {
    const policy = await context.env.DB.prepare("SELECT id, name FROM policies WHERE id = ?").bind(policyId)
      .first<{ id: string; name: string }>();
    if (!policy) return context.json({ error: "Unknown policy" }, 404);
  }
  return auditStandaloneOperation(context.env, "policy.bind", "/api/admin/policy-bindings", async () => {
    const id = crypto.randomUUID();
    await context.env.DB.prepare(
      `INSERT INTO policy_bindings
         (id, target, target_ref, policy_id, bind_user_id, bind_group_id, order_index, mode, negate,
          failure_result, enabled, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, target, targetRef, policyId, bindUserId, bindGroupId, orderIndex, mode,
      negate ? 1 : 0, failureResult, enabled ? 1 : 0, admin.userId, new Date().toISOString()).run();
    return {
      response: Response.json({ binding: { id, target, targetRef, policyId, bindUserId, bindGroupId, order: orderIndex, mode, negate, failureResult, enabled } }, { status: 201 }),
      actorUserId: admin.userId,
      targetUserId: targetRef,
    };
  });
});

policyRoutes.patch("/policy-bindings/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const order = typeof value.order === "number" && Number.isInteger(value.order) && value.order >= 0 && value.order <= 999
    ? value.order : null;
  const mode = value.mode === "any" ? "any" : value.mode === "all" ? "all" : null;
  const negate = value.negate === undefined ? null : value.negate === true ? 1 : 0;
  const failureResult = value.failureResult === "pass" ? "pass" : value.failureResult === "fail" ? "fail" : null;
  const enabled = value.enabled === undefined ? null : value.enabled === true ? 1 : 0;
  return auditStandaloneOperation(context.env, "policy.bind.update", context.req.path, async () => {
    const updated = await context.env.DB.prepare(
      `UPDATE policy_bindings
       SET order_index = COALESCE(?, order_index), mode = COALESCE(?, mode), negate = COALESCE(?, negate),
           failure_result = COALESCE(?, failure_result), enabled = COALESCE(?, enabled)
       WHERE id = ?`,
    ).bind(order, mode, negate, failureResult, enabled, id).run();
    if (updated.meta.changes !== 1) {
      return { response: Response.json({ error: "Binding not found" }, { status: 404 }), actorUserId: admin.userId };
    }
    const row = await context.env.DB.prepare(
      `SELECT id, target, target_ref AS targetRef, policy_id AS policyId, bind_user_id AS bindUserId,
              bind_group_id AS bindGroupId, order_index AS orderIndex, mode, negate,
              failure_result AS failureResult, enabled FROM policy_bindings WHERE id = ?`,
    ).bind(id).first<Record<string, unknown>>();
    return {
      response: Response.json({ binding: { ...row, negate: row?.negate === 1, enabled: row?.enabled === 1 } }),
      actorUserId: admin.userId,
      targetUserId: id,
    };
  });
});

policyRoutes.delete("/policy-bindings/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  return auditStandaloneOperation(context.env, "policy.unbind", context.req.path, async () => {
    const removed = await context.env.DB.prepare("DELETE FROM policy_bindings WHERE id = ?").bind(id).run();
    return {
      response: removed.meta.changes === 1 ? Response.json({ deleted: true }) : Response.json({ error: "Binding not found" }, { status: 404 }),
      actorUserId: admin.userId,
      targetUserId: id,
    };
  });
});

export type { BindingTarget };
