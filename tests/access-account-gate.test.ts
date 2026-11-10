import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../src/db/schema";
import { createAccount } from "../src/accounts/store";
import {
  evaluateAppAccess,
  loadAppAccessPolicy,
  upsertAppAccessPolicy,
  type AppAccessPolicy,
} from "../src/access/policies";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

async function seededEnv(): Promise<Env & { accountId: string }> {
  const testD1 = createTestD1();
  const env = { DB: testD1.db } as unknown as Env;
  await ensureApplicationTables(env);
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY NOT NULL)').run();
  await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" });
  const row = await env.DB.prepare("SELECT account_id AS accountId FROM account_members WHERE user_id = 'u1'")
    .first<{ accountId: string }>();
  await env.DB.prepare(
    'INSERT INTO "user" (id) VALUES (?)',
  ).bind("u2").run();
  await env.DB.prepare(
    "INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at) VALUES ('g1', 'eng', '', 'u1', '2026-01-01', '2026-01-01')",
  ).run();
  return { ...env, accountId: row!.accountId } as Env & { accountId: string };
}

function policy(overrides: Partial<AppAccessPolicy> = {}): AppAccessPolicy {
  return {
    subject: "saml:https://sp.example.com",
    allowedMethods: "password,passkey",
    sessionTtlSeconds: null,
    bypassWindowSeconds: 28800,
    enforcementMode: "enforce",
    requireMfa: false,
    groups: [],
    requiredAccount: null,
    ...overrides,
  };
}

describe("per-account access gate", () => {
  test("a required account admits only its members", async () => {
    const env = await seededEnv();
    await upsertAppAccessPolicy(env, policy({ requiredAccount: env.accountId }), "u1");
    const stored = await loadAppAccessPolicy(env, "saml:https://sp.example.com");
    expect(stored?.requiredAccount).toBe(env.accountId);

    // A member passes (u1 is the account creator/admin member) even though
    // they belong to no required group. The account gate is a membership
    // requirement, not a group grant: temporal grants bypass only the group
    // side, never this gate.
    const member = await evaluateAppAccess(env, stored!, "u1");
    expect(member.allowed).toBe(true);
    const nonMember = await evaluateAppAccess(env, stored!, "u2");
    expect(nonMember.allowed).toBe(false);
    expect(nonMember.reason).toContain("required account");
  });

  test("the gate is nullable: existing platform-wide policies keep working", async () => {
    const env = await seededEnv();
    await upsertAppAccessPolicy(env, policy({ groups: ["g1"], requiredAccount: null }), "u1");
    const stored = await loadAppAccessPolicy(env, "saml:https://sp.example.com");
    expect(stored?.requiredAccount).toBeNull();
    const outsider = await evaluateAppAccess(env, stored!, "u2");
    expect(outsider.allowed).toBe(false);
    expect(outsider.reason).toContain("required group");
  });

  test("upserting a policy for a nonexistent account is rejected", async () => {
    const env = await seededEnv();
    await expect(
      upsertAppAccessPolicy(env, policy({ requiredAccount: "missing-account" }), "u1"),
    ).rejects.toThrow("Required account does not exist");
  });

  test("observe mode lets an account-gate miss through with an observed outcome", async () => {
    const env = await seededEnv();
    await upsertAppAccessPolicy(env, policy({ requiredAccount: env.accountId, enforcementMode: "observe" }), "u1");
    const stored = await loadAppAccessPolicy(env, "saml:https://sp.example.com");
    const outcome = await evaluateAppAccess(env, stored!, "u2");
    expect(outcome).toEqual({ allowed: true, observedOnly: true, reason: "account gate would reject (observe mode)" });
  });
});
