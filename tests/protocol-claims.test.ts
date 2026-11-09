import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../src/db/schema";
import { switchActiveAccount } from "../src/accounts/store";
import { setObjectAttributes } from "../src/objects/attributes";
import {
  activeAccountClaim,
  claimNamespace,
  jwtPayloadRelease,
  oidcClaimRelease,
  samlAttributeRelease,
  samlAttributeNames,
  userAttributesClaim,
} from "../src/claims/protocol-claims";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

async function seededEnv(flags: { account: boolean; attributes: boolean }): Promise<Env> {
  const testD1 = createTestD1();
  const env = {
    DB: testD1.db,
    AUTH_BASE_URL: "https://auth.example.test",
    ENABLE_ACCOUNT_CLAIMS: flags.account ? "true" : undefined,
    ENABLE_ATTRIBUTE_CLAIMS: flags.attributes ? "true" : undefined,
  } as unknown as Env;
  await ensureApplicationTables(env);
  await testD1.sqlite.exec('CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY NOT NULL)');
  await env.DB.prepare("INSERT INTO \"user\" (id) VALUES ('u1')").run();
  await env.DB.prepare(
    `INSERT INTO accounts (id, name, description, created_by, created_at, updated_at)
     VALUES ('acc-1', 'platform', '', 'u1', '2026-01-01', '2026-01-01')`,
  ).run();
  await env.DB.prepare(
    `INSERT INTO account_members (account_id, user_id, role, granted_by, granted_at)
     VALUES ('acc-1', 'u1', 'admin', 'u1', '2026-01-01')`,
  ).run();
  await switchActiveAccount(env, "tok-1", "sess-1", "u1", "acc-1");
  await setObjectAttributes(env, "user", "u1", { team: "platform", level: 3, offboarded: null }, "u1");
  return env;
}

describe("fail-closed claim release", () => {
  test("without flags nothing is released", async () => {
    const env = await seededEnv({ account: false, attributes: false });
    expect(await activeAccountClaim(env, "sess-1")).toEqual({});
    expect(await userAttributesClaim(env, "u1")).toEqual({});
    expect(await oidcClaimRelease(env, "sess-1", "u1")).toEqual({});
    expect(await samlAttributeRelease(env, "tok-1", "sess-1", "u1")).toEqual([]);
  });
});

describe("active account claim", () => {
  test("releases the namespaced structured claim for a switched session", async () => {
    const env = await seededEnv({ account: true, attributes: false });
    const claim = await activeAccountClaim(env, "sess-1");
    expect(claim).toEqual({
      "https://auth.example.test/claims/active-account": { id: "acc-1", name: "platform", role: "admin" },
    });
    // A session that never switched, or an unknown one, releases nothing.
    expect(await activeAccountClaim(env, "sess-unknown")).toEqual({});
    expect(await activeAccountClaim(env, null)).toEqual({});
  });
});

describe("user attributes claim", () => {
  test("releases the flat attribute object, null values included", async () => {
    const env = await seededEnv({ account: false, attributes: true });
    const claim = await userAttributesClaim(env, "u1");
    expect(claim).toEqual({
      "https://auth.example.test/claims/attributes": { team: "platform", level: 3, offboarded: null },
    });
  });
});

describe("merged OIDC release", () => {
  test("combines both claims, keyed per surface", async () => {
    const env = await seededEnv({ account: true, attributes: true });
    const claims = await oidcClaimRelease(env, "sess-1", "u1");
    expect(Object.keys(claims).sort()).toEqual([
      "https://auth.example.test/claims/active-account",
      "https://auth.example.test/claims/attributes",
    ]);
  });
});

describe("SAML attribute release", () => {
  test("emits account and primitive user attributes as sorted strings", async () => {
    const env = await seededEnv({ account: true, attributes: true });
    const attributes = await samlAttributeRelease(env, "tok-1", "sess-1", "u1");
    const names = samlAttributeNames(env);
    // Null entries are skipped; primitives are stringified; sorted by name.
    expect(attributes).toEqual([
      { name: "https://auth.example.test/claims/active-account-id", value: "acc-1" },
      { name: "https://auth.example.test/claims/active-account-name", value: "platform" },
      { name: "https://auth.example.test/claims/active-account-role", value: "admin" },
      { name: `${names.attributePrefix}/level`, value: "3" },
      { name: `${names.attributePrefix}/team`, value: "platform" },
    ]);
    expect(attributes.map((attribute) => attribute.name)).toEqual(
      attributes.map((attribute) => attribute.name),
    );
  });
});

describe("JWT payload release", () => {
  test("preserves the built-in user object and appends released claims", async () => {
    const env = await seededEnv({ account: true, attributes: true });
    const user = { id: "u1", email: "u1@example.test", role: "user" };
    const payload = await jwtPayloadRelease(env, { user, session: { id: "sess-1", token: "tok-1" } });
    expect(payload).toEqual({
      ...user,
      "https://auth.example.test/claims/active-account": { id: "acc-1", name: "platform", role: "admin" },
      "https://auth.example.test/claims/attributes": { team: "platform", level: 3, offboarded: null },
    });
    // Without flags the payload is exactly the built-in user object.
    const closed = await seededEnv({ account: false, attributes: false });
    expect(await jwtPayloadRelease(closed, { user, session: { id: "sess-1", token: "tok-1" } })).toEqual(user);
  });
});

describe("claim namespace", () => {
  test("derives from the configured IdP origin", () => {
    expect(claimNamespace({ AUTH_BASE_URL: "https://auth.example.test" } as unknown as Env)).toBe(
      "https://auth.example.test/claims",
    );
  });
});
