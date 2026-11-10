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
