/**
 * SSO-flow flag and password-write reputation accounting tests:
 * `ak_is_sso_flow` is true only at application (SSO) policy evaluations and
 * failed password writes move reputation just like failed logins.
 *
 * `bun test tests/policies/sso-flow.test.ts`
 */

import { describe, expect, test } from "bun:test";
import { createTestD1 } from "../test-d1";

type TestD1Db = ReturnType<typeof createTestD1>["db"];

import { ensureApplicationTables } from "../../src/db/schema";
import { evaluateAppAccess, upsertAppAccessPolicy } from "../../src/access/policies";
import type { AppAccessPolicy } from "../../src/access/policies";
import { createPasswordPolicyHooks } from "../../src/policies/auth-hooks";
import { reputationScore } from "../../src/policies/reputation";
import { evaluateTyped } from "../../src/policies/registry";

async function envStub(): Promise<{ env: never; db: TestD1Db }> {
  const db = createTestD1().db;
  await ensureApplicationTables({ DB: db } as never);
  return { env: { DB: db, REPUTATION_EXPIRY_HOURS: "72" } as never, db };
}

async function seedUser(db: TestD1Db, id: string): Promise<void> {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY, email TEXT, name TEXT, username TEXT, role TEXT, banned TEXT)`,
  ).run();
  await db.prepare(
    `INSERT OR IGNORE INTO "user" (id, email, name, username, role) VALUES (?, ?, ?, ?, 'user')`,
  ).bind(id, `${id}@example.test`, id, id).run();
}

const SUBJECT = "oidc:sso-flag";

describe("ak_is_sso_flow flag", () => {
  test("true in evaluateAppAccess, false on plain evaluations", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-sso");
    // A bound expression policy that passes exactly when the flow flag is set.
    const policyId = crypto.randomUUID();
    await db.prepare(
      `INSERT INTO policies (id, name, type, config, enabled, execution_logging, created_by, created_at)
       VALUES (?, ?, 'expression', ?, 1, 0, 'admin', ?)`,
    ).bind(policyId, "sso-flag-requires-true", JSON.stringify({ expression: "ak_is_sso_flow" }), new Date().toISOString()).run();
    await db.prepare(
      `INSERT INTO policy_bindings
         (id, target, target_ref, policy_id, bind_user_id, bind_group_id, order_index, mode, negate,
          failure_result, enabled, created_by, created_at)
       VALUES (?, 'application', ?, ?, NULL, NULL, 0, 'all', 0, 'fail', 1, 'admin', ?)`,
    ).bind(crypto.randomUUID(), SUBJECT, policyId, new Date().toISOString()).run();

    const accessPolicy: AppAccessPolicy = {
      subject: SUBJECT,
      allowedMethods: "password",
      sessionTtlSeconds: null,
      bypassWindowSeconds: 0,
      enforcementMode: "enforce",
      requireMfa: false,
      mfaMethods: [],
      requiredAccount: null,
      groups: [],
    };
    await upsertAppAccessPolicy(env as never, { ...accessPolicy, mfaMethods: [] }, "admin");

    // SSO surface: the flag is on, so the expression passes and access is allowed.
    const sso = await evaluateAppAccess(env as never, accessPolicy, "u-sso", { clientIp: "203.0.113.4" });
    expect(sso.allowed).toBe(true);
    expect(sso.reason).toBeNull();

    // Plain evaluation (no SSO surface): the same expression fails.
    const plain = await evaluateTyped(env as never, {
      id: policyId,
      name: "sso-flag-requires-true",
      type: "expression",
      config: { expression: "ak_is_sso_flow" },
      enabled: true,
      executionLogging: false,
    }, { user: null, clientIp: null, subject: null, context: {} } as never).catch(() => null);
    expect(plain?.passing).toBe(false);
  });
});

describe("password-write reputation accounting", () => {
  test("a failed password write moves ip and target-identity reputation", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-rep");
    const hooks = createPasswordPolicyHooks(env as never);
    const headers = new Headers({ "cf-connecting-ip": "198.51.100.77" });
    await hooks.after({
      path: "/change-password",
      body: { userId: "u-rep", currentPassword: "wrong" },
      headers,
      returned: new Response(null, { status: 400 }),
    });
    expect(await reputationScore(env as never, "ip", "198.51.100.77")).toBe(-1);
    expect(await reputationScore(env as never, "username", "u-rep@example.test")).toBe(-1);

    // A succeeding write does not increment reputation.
    await hooks.after({
      path: "/change-password",
      body: { userId: "u-rep", newPassword: "Uncommon-Phrase-77#" },
      headers,
      returned: new Response(null, { status: 200 }),
    });
    expect(await reputationScore(env as never, "ip", "198.51.100.77")).toBe(-1);
  });
});
