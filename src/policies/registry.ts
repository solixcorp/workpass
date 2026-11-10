/**
 * Typed-policy registry (docs/design/authentik-policies.md): per-type config
 * validation and evaluation dispatch. Each type owns its config shape; the
 * engine only routes.
 */

import type { Env } from "../env";
import {
  DEFAULT_STEP_BUDGET,
  evaluateExpression,
} from "./expression";
import { buildGlobals } from "./helpers";
import type { PolicyEvaluationContext, PolicyRow } from "./types";
export interface RuntimePolicyResult { passing: boolean; messages: string[]; rawResult: unknown }

export interface PolicyResult {
  passing: boolean;
  messages: string[];
  rawResult?: unknown;
}

const RESERVED_CONTEXT_KEY = "__ak_call_depth";

const callDepths = new WeakMap<object, number>();
const MAX_CALL_DEPTH = 4;

export function implementedTypes(): string[] {
  return ["expression"];
}

export function validatePolicyConfig(type: string, config: unknown): { config: unknown } {
  if (type === "expression") {
    const value = (config ?? {}) as Record<string, unknown>;
    const expression = typeof value.expression === "string" ? value.expression : "";
    if (expression.trim().length === 0) throw new Error("expression config requires an 'expression' body");
    if (expression.length > 20_000) throw new Error("expression may not exceed 20000 characters");
    let stepBudget = DEFAULT_STEP_BUDGET;
    if (value.step_budget !== undefined) {
      if (typeof value.step_budget !== "number" || !Number.isInteger(value.step_budget) ||
          value.step_budget < 1_000 || value.step_budget > 1_000_000) {
        throw new Error("step_budget must be an integer between 1000 and 1000000");
      }
      stepBudget = value.step_budget;
    }
    return { config: { expression, step_budget: stepBudget } };
  }
  throw new Error(`policy type ${type} is not implemented yet`);
}

export async function evaluateTyped(
  env: Env,
  policy: PolicyRow,
  context: PolicyEvaluationContext,
  budget: number,
): Promise<PolicyResult> {
  const config = (policy.config ?? {}) as Record<string, unknown>;
  switch (policy.type) {
    case "expression": {
      const expression = typeof config.expression === "string" ? config.expression : "";
      const stepBudget = typeof config.step_budget === "number"
        ? Math.min(Math.max(config.step_budget, 1_000), budget * 4)
        : DEFAULT_STEP_BUDGET;
      const depthMap = callDepths.get(context.context) ?? 0;
      const messages: string[] = [];
      const runtime = {
        messages,
        callPolicyByName: async (name: string, kwargs: Record<string, unknown>) => {
          if (depthMap >= MAX_CALL_DEPTH) throw new Error("policy call depth exceeded");
          const row = await env.DB.prepare(
            "SELECT id, name, type, config, enabled, execution_logging AS executionLogging FROM policies WHERE name = ? LIMIT 1",
          ).bind(name).first<{ id: string; name: string; type: string; config: string; enabled: number; executionLogging: number }>();
          if (!row) throw new Error(`no policy named ${JSON.stringify(name)}`);
          if (!row.enabled) return { passing: true, messages: [`policy ${name} is disabled`], rawResult: null } as RuntimePolicyResult;
          const childContext: PolicyEvaluationContext = {
            ...context,
            context: { ...context.context, ...kwargs },
          };
          callDepths.set(childContext.context, depthMap + 1);
          return await evaluateTyped(
            env,
            {
              id: row.id, name: row.name, type: row.type,
              config: JSON.parse(row.config ?? "{}") as unknown,
              enabled: true, executionLogging: row.executionLogging === 1,
            },
            childContext,
            budget,
          );
        },
      };
      const result = await evaluateExpression(
        expression,
        () => buildGlobals(runtime, env, context),
        stepBudget,
      );
      if (typeof result.value !== "boolean") {
        throw new Error("expression policies must return a boolean");
      }
      return { passing: result.value, messages };
    }
    default:
      throw new Error(`policy type ${policy.type} is not implemented yet`);
  }
}

export { RESERVED_CONTEXT_KEY };
