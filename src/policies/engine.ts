/**
 * The policy engine (docs/design/authentik-policies.md): ordered bindings with
 * authentik semantics — ascending order, disabled bindings skipped, direct
 * user/group binds alongside policy binds, an `all`/`any` mode read from the
 * lowest-order binding, negate flipping only the boolean, failure-result
 * deciding how policy errors land, and an empty binding set meaning pass.
 *
 * Typed policies dispatch through the registry; expression policies run on the
 * bounded interpreter. Evaluations always terminate (step budget) and never
 * touch host state.
 */

import type { Env } from "../env";
import { evaluateTyped } from "./registry";
import type { BindingTarget, PolicyEvaluationContext, PolicyRow, PolicyUserSnapshot } from "./types";

export type { BindingTarget };
export type { PolicyRow };

export interface PolicyBinding {
  id: string;
  target: BindingTarget;
  targetRef: string;
  policy: PolicyRow | null;
  bindUserId: string | null;
  bindGroupId: string | null;
  orderIndex: number;
  mode: "all" | "any";
  negate: boolean;
  failureResult: "fail" | "pass";
  enabled: boolean;
}

export interface PolicyResult {
  passing: boolean;
  messages: string[];
}

const DEFAULT_BUDGET = 50_000;

export async function loadUserSnapshot(env: Env, userId: string): Promise<PolicyUserSnapshot | null> {
  try {
    const row = await env.DB.prepare(
      `SELECT id, email, name, username, role FROM "user" WHERE id = ? LIMIT 1`,
    ).bind(userId).first<{ id: string; email: string; name: string; username: string | null; role: string | null }>();
    if (!row) return null;
    return {
      id: row.id,
      email: row.email,
      name: row.name,
      username: row.username ?? row.email,
      attributes: {},
      roles: typeof row.role === "string" ? row.role.split(",").filter(Boolean) : [],
    };
  } catch {
    // Partial or broken user storage degrades to an anonymous snapshot; bound
    // policies see request.user = null and the failure result rules apply.
    return null;
  }
}

export async function loadBindingsForTarget(env: Env, target: BindingTarget, targetRef: string): Promise<PolicyBinding[]> {
  const rows = await env.DB.prepare(
    `SELECT b.id, b.target, b.target_ref AS targetRef, b.order_index AS orderIndex,
            b.mode, b.negate, b.failure_result AS failureResult, b.enabled,
            b.bind_user_id AS bindUserId, b.bind_group_id AS bindGroupId,
            p.id AS p_id, p.name AS p_name, p.type AS p_type, p.config AS p_config,
            p.enabled AS p_enabled, p.execution_logging AS p_executionLogging
     FROM policy_bindings b
     LEFT JOIN policies p ON p.id = b.policy_id
     WHERE b.target = ? AND b.target_ref = ?
     ORDER BY b.order_index ASC, b.id ASC
     LIMIT 100`,
  ).bind(target, targetRef).all<Record<string, unknown>>();
  return rows.results.map((row) => ({
    id: row.id as string,
    target: row.targetRef !== undefined ? (row.target as BindingTarget) : (row.target as BindingTarget),
    targetRef: row.targetRef as string,
    policy: row.p_id
      ? {
          id: row.p_id as string,
          name: row.p_name as string,
          type: row.p_type as string,
          config: JSON.parse((row.p_config as string) ?? "{}") as unknown,
          enabled: row.p_enabled === 1,
          executionLogging: row.p_executionLogging === 1,
        }
      : null,
    bindUserId: row.bindUserId as string | null,
    bindGroupId: row.bindGroupId as string | null,
    orderIndex: row.orderIndex as number,
    mode: (row.mode as "all" | "any") ?? "all",
    negate: row.negate === 1,
    failureResult: (row.failureResult as "fail" | "pass") ?? "fail",
    enabled: row.enabled === 1,
  }));
}

/**
 * Evaluate every enabled binding for the target. Returns the collected
 * pass/fail outcome plus every message, in binding order.
 */
export async function evaluateBoundPolicies(
  env: Env,
  target: BindingTarget,
  targetRef: string,
  context: PolicyEvaluationContext,
  budget = DEFAULT_BUDGET,
): Promise<PolicyResult & { bindings: number }> {
  const bindings = (await loadBindingsForTarget(env, target, targetRef)).filter((binding) => binding.enabled);
  if (bindings.length === 0) return { passing: true, messages: [], bindings: 0 };
  const messages: string[] = [];
  // The mode is a property of the binding target; authentik reads it from the
  // binding set, so the lowest-order binding decides.
  const mode = bindings[0]!.mode;
  let sawFailure = false;
  let sawPass = false;
  for (const binding of bindings) {
    let outcome: { passing: boolean; messages: string[] };
    try {
      if (binding.bindGroupId) {
        // A direct group bind is a membership check against the acting user.
        const member = context.user ? (await env.DB.prepare(
          "SELECT 1 FROM directory_group_members WHERE group_id = ? AND user_id = ? LIMIT 1",
        ).bind(binding.bindGroupId, context.user.id).first()) !== null : false;
        outcome = { passing: member, messages: [] };
      } else if (binding.bindUserId) {
        outcome = { passing: bindUserIdMatches(context, binding.bindUserId), messages: [] };
      } else if (binding.policy) {
        if (!binding.policy.enabled) {
          // A disabled policy keeps its binding alive but cannot run; treat the
          // pairing as skipped (pass) so the gate does not silently harden.
          outcome = { passing: true, messages: [`policy ${binding.policy.name} is disabled`] };
        } else {
          outcome = await evaluateTyped(env, binding.policy, context, budget);
          if (binding.policy.executionLogging) {
            console.log("policy execution", {
              policy: binding.policy.name,
              passing: outcome.passing,
              messages: outcome.messages,
            });
          }
        }
      } else {
        outcome = { passing: true, messages: [] };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown policy error";
      if (binding.failureResult === "pass") {
        outcome = { passing: true, messages: [`policy error ignored (failure result = pass): ${message}`] };
      } else {
        outcome = { passing: false, messages: [`policy error: ${message}`] };
      }
    }
    const passing = binding.negate ? !outcome.passing : outcome.passing;
    messages.push(...outcome.messages);
    if (!passing) sawFailure = true;
    if (passing && mode === "any") sawPass = true;
    // `any` mode short-circuits on the first pass; `all` mode keeps evaluating
    // so every user-visible problem is collected (authentik collects messages
    // across bindings instead of stopping at the first failure).
    if (mode === "any" && sawPass) break;
  }
  const passing = mode === "all" ? !sawFailure : sawPass;
  return { passing, messages, bindings: bindings.length };
}

function bindUserIdMatches(context: PolicyEvaluationContext, bindUserId: string): boolean {
  return context.user?.id === bindUserId;
}
