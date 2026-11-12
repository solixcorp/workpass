/**
 * Admin screen backing for the password rules shown at account activation.
 *
 * The rules are not stored separately: this reads and writes one `password`
 * policy (fixed name) bound to the password-entry surface, the same policy
 * engine every other password rule uses. The screen definition (fields, ranges,
 * copy) is sent with the values, so the console renders from it.
 *
 * Only rules the browser can check are offered. OPAQUE keeps the password from
 * the server, so breach and strength checks, which need the plaintext, cannot
 * run on this path and are not editable here (a value set elsewhere is kept).
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { validatePasswordConfig } from "./password";
import { PASSWORD_ENTRY_REF } from "./password-entry";
import { activeAndBoundPasswordRules } from "../security/account-activation";

export const passwordRulesRoutes = new Hono<{ Bindings: Env }>();

const POLICY_NAME = "workpass-password-rules";

// OPAQUE registration records do not reveal a password to the server; a
// modified client can bypass browser checks, so this is not server enforcement.
const ENFORCEMENT_SCOPE = {
  plaintextPasswordWrites: "server_verified",
  opaqueActivation: "browser_advisory",
  opaquePasswordChange: "browser_advisory",
} as const;

const FIELDS = [
  { name: "minLength", label: "최소 길이", min: 8, max: 128, unit: "자" },
  { name: "minUpper", label: "대문자", min: 0, max: 16, unit: "개 이상" },
  { name: "minLower", label: "소문자", min: 0, max: 16, unit: "개 이상" },
  { name: "minDigit", label: "숫자", min: 0, max: 16, unit: "개 이상" },
  { name: "minSymbol", label: "기호", min: 0, max: 16, unit: "개 이상" },
] as const;

type FieldName = (typeof FIELDS)[number]["name"];

async function loadOwnPolicy(env: Env): Promise<{ id: string; config: Record<string, unknown> } | null> {
  const row = await env.DB.prepare("SELECT id, config FROM policies WHERE name = ? LIMIT 1")
    .bind(POLICY_NAME).first<{ id: string; config: string }>();
  if (!row) return null;
  try {
    return { id: row.id, config: JSON.parse(row.config) as Record<string, unknown> };
  } catch {
    return { id: row.id, config: {} };
  }
}

async function otherBoundPolicies(env: Env, ownId: string | null): Promise<number> {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM policy_bindings b JOIN policies p ON p.id = b.policy_id
     WHERE b.target = 'password_entry' AND b.target_ref = ? AND b.enabled = 1 AND p.enabled = 1
       AND p.type = 'password' AND p.id <> ?`,
  ).bind(PASSWORD_ENTRY_REF, ownId ?? "").first<{ count: number }>().catch(() => null);
  return row?.count ?? 0;
}

passwordRulesRoutes.use("/password-rules", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

passwordRulesRoutes.get("/password-rules", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const own = await loadOwnPolicy(context.env);
  const config = validatePasswordConfig(own?.config ?? {});
  const effective = await activeAndBoundPasswordRules(context.env);
  return context.json({
    title: "비밀번호 규칙",
    enforcementScope: ENFORCEMENT_SCOPE,
    description: "계정 활성화와 비밀번호 설정 화면에 적용됩니다. 비밀번호는 서버로 전송되지 않아 브라우저에서 검사합니다.",
    fields: FIELDS.map((field) => ({ ...field, value: config[field.name] })),
    stored: own !== null,
    effective: Object.fromEntries(FIELDS.map((field) => [field.name, effective[field.name]])),
    otherPolicies: await otherBoundPolicies(context.env, own?.id ?? null),
  });
});

passwordRulesRoutes.put("/password-rules", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "요청을 읽을 수 없습니다." }, 400);
  }
  const submitted = ((body as { values?: unknown } | null)?.values ?? {}) as Record<string, unknown>;

  const own = await loadOwnPolicy(context.env);
  const next: Record<string, unknown> = { ...(own?.config ?? {}) };
  for (const field of FIELDS) {
    if (submitted[field.name] === undefined) continue;
    const value = submitted[field.name];
    if (typeof value !== "number" || !Number.isInteger(value) || value < field.min || value > field.max) {
      return context.json({ error: `${field.label}은(는) ${field.min}에서 ${field.max} 사이의 정수여야 합니다.` }, 400);
    }
    next[field.name as FieldName] = value;
  }
  let validated;
  try {
    validated = validatePasswordConfig(next);
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "잘못된 값입니다." }, 400);
  }
  // Rules that need the plaintext stay as stored; this screen never turns them on.
  const stored = { ...next, ...validated };

  return auditStandaloneOperation(context.env, "policy.password_rules.update", "/api/admin/password-rules", async () => {
    const now = new Date().toISOString();
    let policyId = own?.id;
    if (policyId) {
      await context.env.DB.prepare("UPDATE policies SET config = ?, enabled = 1 WHERE id = ?")
        .bind(JSON.stringify(stored), policyId).run();
    } else {
      policyId = crypto.randomUUID();
      await context.env.DB.prepare(
        `INSERT INTO policies (id, name, type, config, enabled, execution_logging, created_by, created_at)
         VALUES (?, ?, 'password', ?, 1, 0, ?, ?)`,
      ).bind(policyId, POLICY_NAME, JSON.stringify(stored), actor.userId, now).run();
    }
    const binding = await context.env.DB.prepare(
      "SELECT id FROM policy_bindings WHERE target = 'password_entry' AND target_ref = ? AND policy_id = ? LIMIT 1",
    ).bind(PASSWORD_ENTRY_REF, policyId).first<{ id: string }>();
    if (binding) {
      await context.env.DB.prepare("UPDATE policy_bindings SET enabled = 1 WHERE id = ?").bind(binding.id).run();
    } else {
      await context.env.DB.prepare(
        `INSERT INTO policy_bindings
           (id, target, target_ref, policy_id, bind_user_id, bind_group_id, order_index, mode, negate,
            failure_result, enabled, created_by, created_at)
         VALUES (?, 'password_entry', ?, ?, NULL, NULL, 0, 'all', 0, 'fail', 1, ?, ?)`,
      ).bind(crypto.randomUUID(), PASSWORD_ENTRY_REF, policyId, actor.userId, now).run();
    }
    return {
      response: context.json({ saved: true, enforcementScope: ENFORCEMENT_SCOPE, values: Object.fromEntries(FIELDS.map((field) => [field.name, validated[field.name]])) }),
      actorUserId: actor.userId,
      targetUserId: POLICY_NAME,
    };
  });
});
