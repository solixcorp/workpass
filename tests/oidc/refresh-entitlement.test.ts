import { describe, expect, test } from "bun:test";
import { createTestD1 } from "../test-d1";
import { ensureApplicationTables } from "../../src/db/schema";
import { enforceRefreshEntitlement } from "../../src/auth/routes";
import { revokeOidcTokens } from "../../src/db/oidc-offboarding";
import type { Env } from "../../src/env";

async function fixture() {
  const { db, sqlite } = createTestD1();
  const env = { DB: db, AUTH_BASE_URL: "https://auth.test" } as Env;
  await ensureApplicationTables(env);
  sqlite.exec(`CREATE TABLE "user" (id TEXT PRIMARY KEY, email TEXT, name TEXT, username TEXT, role TEXT);
    CREATE TABLE "oauthRefreshToken" (id TEXT PRIMARY KEY, token TEXT, userId TEXT, clientId TEXT);
    CREATE TABLE "oauthAccessToken" (id TEXT PRIMARY KEY, userId TEXT, clientId TEXT);
    INSERT INTO "user" VALUES ('u', 'u@example.test', 'U', 'u', 'user');`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("secret")));
  const token = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  sqlite.query('INSERT INTO "oauthRefreshToken" VALUES (?, ?, ?, ?)').run("r", token, "u", "client");
  sqlite.exec(`INSERT INTO "oauthAccessToken" VALUES ('a','u','client'), ('b','other','client');
    INSERT INTO app_access_policies (subject, allowed_methods, bypass_window_seconds, enforcement_mode, require_mfa, mfa_methods, updated_by, updated_at)
      VALUES ('oidc:client', 'password', 0, 'enforce', 0, '', 'admin', 'now');
    INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at) VALUES ('group', 'Group', '', 'admin', 'now', 'now');
    INSERT INTO app_policy_groups (subject, group_id) VALUES ('oidc:client', 'group');`);
  return { env, sqlite };
}
function request(grant = "refresh_token") {
  return new Request("https://auth.test/api/auth/oauth2/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: grant, refresh_token: "secret" }) });
}

describe("refresh entitlement", () => {
  test("checks current membership and fails closed on policy errors", async () => {
    const { env, sqlite } = await fixture();
    sqlite.exec("INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES ('group', 'u', 'admin', 'now')");
    expect(await enforceRefreshEntitlement(request(), env)).toBeNull();
    sqlite.exec("DELETE FROM directory_group_members WHERE user_id = 'u'");
    expect((await (await enforceRefreshEntitlement(request(), env))!.json()).error).toBe("invalid_grant");
    expect(sqlite.query("SELECT actor_user_id, target_user_id, event_type, outcome, request_path, event_context FROM audit_events WHERE event_type = 'authorization.refresh_denied'").all()).toEqual([{
      actor_user_id: "u", target_user_id: "u", event_type: "authorization.refresh_denied", outcome: "success", request_path: "/api/auth/oauth2/token", event_context: null,
    }]);
    sqlite.exec("DROP TABLE app_access_policies");
    expect((await enforceRefreshEntitlement(request(), env))?.status).toBe(400);
    expect(sqlite.query("SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'authorization.refresh_denied' AND actor_user_id = 'u'").get()).toEqual({ count: 2 });
    expect(await enforceRefreshEntitlement(request("client_credentials"), env)).toBeNull();
  });

  test("revokes only the selected user's client tokens", async () => {
    const { env, sqlite } = await fixture();
    await revokeOidcTokens(env, "client", "u");
    expect(sqlite.query('SELECT id FROM "oauthRefreshToken"').all()).toEqual([]);
    expect(sqlite.query('SELECT id FROM "oauthAccessToken"').all()).toEqual([{ id: "b" }]);
  });
});
