import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../src/db/schema";
import { createAccount, switchActiveAccount } from "../src/accounts/store";
import { setObjectAttributes } from "../src/objects/attributes";
import {
  deleteClaimReleasePolicy,
  getClaimReleasePolicy,
  listClaimReleasePolicies,
  upsertClaimReleasePolicy,
  validateClaimReleasePolicy,
} from "../src/claims/release-policy";
import {
  activeAccountClaimForSubject,
  oidcClaimRelease,
  oidcClaimReleaseForSubject,
  userAttributesClaimForSubject,
} from "../src/claims/protocol-claims";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

async function seededEnv(): Promise<Env> {
  const testD1 = createTestD1();
  const env = {
    DB: testD1.db,
    AUTH_BASE_URL: "https://auth.example.test",
    ENABLE_ACCOUNT_CLAIMS: "true",
    ENABLE_ATTRIBUTE_CLAIMS: "true",
  } as unknown as Env;
  await ensureApplicationTables(env);
  await testD1.sqlite.exec('CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY NOT NULL)');
  await env.DB.prepare("INSERT INTO \"user\" (id) VALUES ('u1')").run();
  await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" });
  // account id is random; recover it from the members table.
  const row = await env.DB.prepare("SELECT account_id AS accountId FROM account_members WHERE user_id = 'u1'").first<{ accountId: string }>();
  await setObjectAttributes(env, "user", "u1", { team: "core" }, "u1");
  await switchActiveAccount(env, "tok-1", "sess-1", "u1", row!.accountId);
  return env;
}

describe("claim release policy", () => {
  test("no policy row keeps the flag-only default for every subject", async () => {
    const env = await seededEnv();
    const claims = await oidcClaimReleaseForSubject(env, "sess-1", "u1", "oidc:client-1");
    expect(Object.keys(claims)).toHaveLength(2);
  });

  test("a policy row narrows the kinds without widening beyond the flags", async () => {
    const env = await seededEnv();
    await upsertClaimReleasePolicy(env, { subject: "oidc:client-1", allowAccountClaims: false, allowUserAttributes: true }, "u1");
    const narrowed = await oidcClaimReleaseForSubject(env, "sess-1", "u1", "oidc:client-1");
    expect(Object.keys(narrowed)).toEqual(["https://auth.example.test/claims/attributes"]);
    // Another client without a row still receives everything.
    const untouched = await oidcClaimReleaseForSubject(env, "sess-1", "u1", "oidc:client-2");
    expect(Object.keys(untouched)).toHaveLength(2);
    // Removing the policy restores the default.
    expect(await deleteClaimReleasePolicy(env, "oidc:client-1")).toBe(true);
    const restored = await oidcClaimReleaseForSubject(env, "sess-1", "u1", "oidc:client-1");
    expect(Object.keys(restored)).toHaveLength(2);
  });

  test("the gate is an AND: flags off beat a permissive policy row", async () => {
    const env = await seededEnv();
    await upsertClaimReleasePolicy(env, { subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true }, "u1");
    delete (env as Record<string, unknown>).ENABLE_ACCOUNT_CLAIMS;
    // The merged release keeps only the attribute kind: the account claim is
    // dead even though the policy row is permissive.
    const claims = await oidcClaimReleaseForSubject(env, "sess-1", "u1", "oidc:client-1");
    expect(claims).toEqual({
      "https://auth.example.test/claims/attributes": { team: "core" },
    });
    expect(await activeAccountClaimForSubject(env, "sess-1", "oidc:client-1")).toEqual({});
  });

  test("invalid subjects are rejected and listed policies round-trip", async () => {
    const env = await seededEnv();
    expect(() => validateClaimReleasePolicy({ subject: "nonsense-subject", allowAccountClaims: true, allowUserAttributes: true })).toThrow();
    await upsertClaimReleasePolicy(env, { subject: "saml:https://sp.example.com", allowAccountClaims: true, allowUserAttributes: false }, "u1");
    const listed = await listClaimReleasePolicies(env);
    expect(listed.map((policy) => policy.subject)).toEqual(["saml:https://sp.example.com"]);
    const fetched = await getClaimReleasePolicy(env, "saml:https://sp.example.com");
    expect(fetched?.allowUserAttributes).toBe(false);
  });
});

describe("per-attribute allowlist", () => {
  test("corrupt stored allowlists deny attributes without changing the flag-only path", async () => {
    const env = await seededEnv();
    await upsertClaimReleasePolicy(env, { subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true }, "u1");
    for (const value of ["", "[\"team\"", "null", "{}", "[42]", "[\"bad key\"]"]) {
      await env.DB.prepare("UPDATE claim_release_policies SET attribute_allowlist = ? WHERE subject = ?").bind(value, "oidc:client-1").run();
      expect(await userAttributesClaimForSubject(env, "u1", "oidc:client-1")).toEqual({});
      expect(await userAttributesClaimForSubject(env, "u1", undefined)).toEqual({ "https://auth.example.test/claims/attributes": { team: "core" } });
    }
  });
  test("an allowlist narrows the released attribute set; null keeps everything", async () => {
    const env = await seededEnv();
    const { userAttributesForSubject } = await import("../src/claims/release-policy");
    const set = { team: "core", level: 3, badge: null };
    expect(await userAttributesForSubject(env, "oidc:client-1", set)).toEqual(set);
    await upsertClaimReleasePolicy(env, {
      subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true,
      attributeAllowlist: ["team", "ghost-key"],
    }, "u1");
    // Only listed keys flow, and unknown allowlist entries release nothing.
    expect(await userAttributesForSubject(env, "oidc:client-1", set)).toEqual({ team: "core" });
    await upsertClaimReleasePolicy(env, {
      subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true,
      attributeAllowlist: [],
    }, "u1");
    expect(await userAttributesForSubject(env, "oidc:client-1", set)).toEqual({});
    await upsertClaimReleasePolicy(env, {
      subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true,
      attributeAllowlist: null,
    }, "u1");
    expect(await userAttributesForSubject(env, "oidc:client-1", set)).toEqual(set);
  });

  test("the merged claim surfaces honor the allowlist", async () => {
    const env = await seededEnv();
    await upsertClaimReleasePolicy(env, {
      subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true,
      attributeAllowlist: ["team"],
    }, "u1");
    const claims = await oidcClaimReleaseForSubject(env, "sess-1", "u1", "oidc:client-1");
    expect(claims["https://auth.example.test/claims/attributes"]).toEqual({ team: "core" });
  });

  test("invalid allowlist inputs are rejected at the write path", async () => {
    const env = await seededEnv();
    await expect(
      upsertClaimReleasePolicy(env, {
        subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true,
        attributeAllowlist: ["bad key with spaces"],
      }, "u1"),
    ).rejects.toThrow("attributeAllowlist keys");
    await expect(
      upsertClaimReleasePolicy(env, {
        subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true,
        attributeAllowlist: Array.from({ length: 33 }, (_, index) => `k${index}`) as string[],
      }, "u1"),
    ).rejects.toThrow("at most 32");
  });
});

describe("group and account attribute release", () => {
  test("the active account's attributes ride on the account gate", async () => {
    const env = await seededEnv();
    const { accountAttributesClaimForSubject } = await import("../src/claims/protocol-claims");
    // No account attributes yet → no claim.
    expect(await accountAttributesClaimForSubject(env, "sess-1", undefined)).toEqual({});
    const accountId = (await env.DB.prepare("SELECT account_id AS id FROM account_members WHERE user_id='u1'").first<{ id: string }>())!.id;
    const { setObjectAttributes } = await import("../src/objects/attributes");
    await setObjectAttributes(env, "account", accountId, { department: "eng" }, "u1");
    // Released when the flag is on, subject-gated with the account kind.
    const open = await accountAttributesClaimForSubject(env, "sess-1", undefined);
    expect(open).toEqual({ "https://auth.example.test/claims/account-attributes": { department: "eng" } });
    await upsertClaimReleasePolicy(env, { subject: "oidc:client-1", allowAccountClaims: true, allowUserAttributes: true, allowAccountAttributes: false }, "u1");
    expect(await accountAttributesClaimForSubject(env, "sess-1", "oidc:client-1")).toEqual({});
  });

  test("group attributes release only the user's membered groups within the size cap", async () => {
    const env = await seededEnv();
    const { groupAttributesClaimForSubject } = await import("../src/claims/protocol-claims");
    for (let index = 1; index <= 3; index += 1) {
      await env.DB.prepare(
        `INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at)
         VALUES ('grp-${index}', 'g${index}', '', 'u1', '2026-01-01', '2026-01-01')`,
      ).run();
    }
    await env.DB.prepare(
      "INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES ('grp-1', 'u1', 'u1', '2026-01-01')",
    ).run();
    const accountId = await env.DB.prepare(
      "SELECT account_id AS id FROM account_members WHERE user_id='u1'",
    ).first<{ id: string }>();
    void accountId;
    await env.DB.prepare(
      `INSERT INTO object_attributes (object_type, object_id, attributes, updated_at)
       VALUES ('group', 'grp-2', '{"cost_center":"c1"}', '2026-01-01')`,
    ).run();
    // The user's groups: only grp-1 (member) and grp-2 (member? no) — grp-2's
    // attributes exist but the user is not its member, so nothing releases.
    expect(await groupAttributesClaimForSubject(env, "u1", undefined)).toEqual({});
    await env.DB.prepare(
      "INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES ('grp-2', 'u1', 'u1', '2026-01-01')",
    ).run();
    const released = await groupAttributesClaimForSubject(env, "u1", undefined);
    expect(released).toEqual({
      "https://auth.example.test/claims/group-attributes": { "grp-2": { cost_center: "c1" } },
    });
    // With the flag off nothing releases.
    delete (env as Record<string, unknown>).ENABLE_ATTRIBUTE_CLAIMS;
    expect(await groupAttributesClaimForSubject(env, "u1", undefined)).toEqual({});
  });
});

describe("subject-aware release surfaces", () => {
  test("the user-surface helpers keep working without a subject", async () => {
    const env = await seededEnv();
    expect(await userAttributesClaimForSubject(env, "u1", undefined)).toEqual({
      "https://auth.example.test/claims/attributes": { team: "core" },
    });
    expect(await userAttributesClaimForSubject(env, "u1", "oidc:client-1")).toEqual({
      "https://auth.example.test/claims/attributes": { team: "core" },
    });
    // Flag-only path (no policy) also still returns from the merged release.
    expect(Object.keys(await oidcClaimRelease(env, "sess-1", "u1"))).toHaveLength(2);
  });
});
