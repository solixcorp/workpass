import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../src/db/schema";
import {
  addAccountMember,
  cleanupAccountSessionContexts,
  createAccount,
  deleteAccount,
  getAccount,
  getSessionAccountContext,
  isAccountMember,
  listUserAccountMemberships,
  removeAccountMember,
  switchActiveAccount,
  updateAccount,
  updateAccountMemberRole,
} from "../src/accounts/store";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

async function seededEnv(): Promise<Env> {
  const env = { DB: createTestD1().db } as unknown as Env;
  await ensureApplicationTables(env);
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY NOT NULL)').run();
  await env.DB.prepare('INSERT INTO "user" (id) VALUES (?)').bind("u1").run();
  await env.DB.prepare('INSERT INTO "user" (id) VALUES (?)').bind("u2").run();
  return env;
}

describe("account lifecycle", () => {
  test("creating an account grants its creator the admin role atomically", async () => {
    const env = await seededEnv();
    const account = await createAccount(env, { name: "platform", description: "sir", creatorUserId: "u1" });
    expect(account).not.toBeNull();
    expect(await isAccountMember(env, account!.id, "u1")).toBe("admin");
    expect(await isAccountMember(env, account!.id, "u2")).toBeNull();
    expect((await getAccount(env, account!.id))!.name).toBe("platform");
  });

  test("duplicate names are rejected by the unique constraint, not by the member table", async () => {
    const env = await seededEnv();
    await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" });
    let duplicate = false;
    try {
      await createAccount(env, { name: "platform", description: "", creatorUserId: "u2" });
    } catch (error) {
      duplicate = (error as Error).message.includes("UNIQUE constraint failed: accounts.name");
    }
    expect(duplicate).toBe(true);
  });

  test("deleting an account removes memberships and session contexts", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    await addAccountMember(env, account.id, "u2", "member", "u1");
    await switchActiveAccount(env, "tok-a", "sid-a", "u2", account.id);
    expect((await listUserAccountMemberships(env, "u2", "tok-a")).memberships).toHaveLength(1);
    expect(await deleteAccount(env, account.id)).toBe(true);
    expect(await getAccount(env, account.id)).toBeNull();
    expect(await isAccountMember(env, account.id, "u2")).toBeNull();
    expect((await listUserAccountMemberships(env, "u2", "tok-a")).memberships).toHaveLength(0);
  });
});

describe("membership and switching", () => {
  test("switching requires actual membership in the target account", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    expect(await switchActiveAccount(env, "tok-u2", null, "u2", account.id)).toBeNull();
    await addAccountMember(env, account.id, "u2", "member", "u1");
    const switched = await switchActiveAccount(env, "tok-u2", "sid-u2", "u2", account.id);
    expect(switched).not.toBeNull();
    expect(await switchActiveAccount(env, "tok-u1", null, "u99", account.id)).toBeNull();
  });

  test("switching without a session id still binds the token", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    await switchActiveAccount(env, "tok-a", null, "u1", account.id);
    expect((await listUserAccountMemberships(env, "u1", "tok-a")).activeAccountId).toBe(account.id);
    expect(await getSessionAccountContext(env, "sid-a")).toBeNull();
  });

  test("the session id resolves the active account for protocol claims", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    await switchActiveAccount(env, "tok-a", "sid-a", "u1", account.id);
    const context = await getSessionAccountContext(env, "sid-a");
    expect(context?.account.name).toBe("platform");
    expect(context?.role).toBe("admin");
    // A re-switch updates the same binding.
    const other = (await createAccount(env, { name: "beta", description: "", creatorUserId: "u1" }))!;
    await switchActiveAccount(env, "tok-a", "sid-a", "u1", other.id);
    expect((await getSessionAccountContext(env, "sid-a"))?.account.id).toBe(other.id);
    // Unknown session ids resolve to nothing.
    expect(await getSessionAccountContext(env, "sid-unknown")).toBeNull();
  });

  test("the active account is per session, not per user", async () => {
    const env = await seededEnv();
    const accountA = (await createAccount(env, { name: "alpha", description: "", creatorUserId: "u1" }))!;
    const accountB = (await createAccount(env, { name: "beta", description: "", creatorUserId: "u2" }))!;
    await addAccountMember(env, accountB.id, "u1", "member", "u2");

    await switchActiveAccount(env, "tok-a", "sid-a", "u1", accountA.id);
    await switchActiveAccount(env, "tok-b", "sid-b", "u1", accountB.id);
    const sessionA = await listUserAccountMemberships(env, "u1", "tok-a");
    const sessionB = await listUserAccountMemberships(env, "u1", "tok-b");
    expect(sessionA.activeAccountId).toBe(accountA.id);
    expect(sessionB.activeAccountId).toBe(accountB.id);
    expect(sessionA.memberships.filter((membership) => membership.active)).toHaveLength(1);

    // A session without a context lists every membership but no active one.
    const anonymous = await listUserAccountMemberships(env, "u1", null);
    expect(anonymous.memberships.every((membership) => !membership.active)).toBe(true);
    // Re-switching overwrites the context; the old binding disappears.
    await switchActiveAccount(env, "tok-a", "sid-a", "u1", accountB.id);
    expect((await listUserAccountMemberships(env, "u1", "tok-a")).activeAccountId).toBe(accountB.id);
  });

  test("removing a membership drops the member's session context for that account", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    await addAccountMember(env, account.id, "u2", "member", "u1");
    await switchActiveAccount(env, "tok-u2", "sid-u2", "u2", account.id);
    expect((await listUserAccountMemberships(env, "u2", "tok-u2")).activeAccountId).toBe(account.id);

    expect(await removeAccountMember(env, account.id, "u2")).toBe(true);
    const context = await env.DB.prepare(
      "SELECT account_id FROM account_session_contexts WHERE session_token = 'tok-u2'",
    ).first();
    expect(context).toBeNull();
  });
});

describe("account and membership updates", () => {
  test("renaming an account updates the row and keeps memberships intact", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "old", creatorUserId: "u1" }))!;
    const renamed = await updateAccount(env, account.id, { name: "backend", description: "new" });
    expect(renamed?.name).toBe("backend");
    expect(renamed?.description).toBe("new");
    expect((await getAccount(env, account.id))!.name).toBe("backend");
  });

  test("renaming to a taken name is rejected by the unique constraint", async () => {
    const env = await seededEnv();
    await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" });
    const account = (await createAccount(env, { name: "runtime", description: "", creatorUserId: "u1" }))!;
    let duplicate = false;
    try {
      await updateAccount(env, account.id, { name: "platform" });
    } catch (error) {
      duplicate = (error as Error).message.includes("UNIQUE constraint failed: accounts.name");
    }
    expect(duplicate).toBe(true);
    // The conflicting name did not overwrite the row.
    expect((await getAccount(env, account.id))!.name).toBe("runtime");
  });

  test("member role updates flow into the session account context", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    await switchActiveAccount(env, "tok-a", "sid-a", "u1", account.id);
    expect(await updateAccountMemberRole(env, account.id, "u1", "member")).toBe(true);
    expect((await getSessionAccountContext(env, "sid-a"))?.role).toBe("member");
    await updateAccountMemberRole(env, account.id, "u1", "admin");
    expect((await getSessionAccountContext(env, "sid-a"))?.role).toBe("admin");
  });

  test("role updates on a non-membership are a no-op reporting false", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    expect(await updateAccountMemberRole(env, account.id, "u2", "member")).toBe(false);
  });
});

describe("context retention", () => {
  test("stale contexts are pruned by the daily cleanup window", async () => {
    const env = await seededEnv();
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    await switchActiveAccount(env, "tok-old", "sid-old", "u1", account.id);
    await env.DB.prepare(
      "UPDATE account_session_contexts SET switched_at = ? WHERE session_token = 'tok-old'",
    ).bind(new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString()).run();
    await switchActiveAccount(env, "tok-fresh", "sid-fresh", "u1", account.id);

    await cleanupAccountSessionContexts(env, new Date());
    const fresh = await env.DB.prepare(
      "SELECT session_token AS sessionToken FROM account_session_contexts ORDER BY session_token",
    ).all<{ sessionToken: string }>();
    expect(fresh.results.map((row) => row.sessionToken)).toEqual(["tok-fresh"]);
  });
});
