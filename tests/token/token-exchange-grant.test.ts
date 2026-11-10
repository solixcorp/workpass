import { describe, expect, test } from "bun:test";
import type { OAuthExtensionGrantHandlerInput } from "@better-auth/oauth-provider";
import type { Env } from "../../src/env";
import { ACCESS_TOKEN_TYPE } from "../../src/token/exchange-authorization";
import { handleTokenExchange } from "../../src/token/grant";

function fixture() {
  const now = Math.floor(Date.now() / 1000);
  let issued = 0;
  let audited = 0;
  const body: Record<string, unknown> = { subject_token: "opaque-token", subject_token_type: ACCESS_TOKEN_TYPE,
    resource: "https://api.example.test/", scope: "read" };
  const token: Record<string, unknown> = { active: true, client_id: "client-a", sub: "user-a", sid: "session-a",
    exp: now + 600, scope: "read write", aud: "https://api.example.test/" };
  let account: { banned: number | null } | null = { banned: 0 };
  let client = { clientId: "client-a", tokenEndpointAuthMethod: "client_secret_basic" };
  const env = { TOKEN_EXCHANGE_ALLOWED_RESOURCES: JSON.stringify({ "client-a": [body.resource] }),
    DB: { prepare(sql: string) { return { bind() { return this; },
      async first() { return account; }, async run() { if (sql.includes("audit_events")) audited++; return {}; } }; } } } as unknown as Env;
  const args = { ctx: { body, context: { internalAdapter: { async findUserById() { return { id: "user-a" }; } },
      adapter: { async findOne() { return { identifier: body.resource, accessTokenTtl: null }; } } } },
    opts: { accessTokenExpiresIn: 300 }, provider: {
      async authenticateClient() { return { client, clientId: client.clientId }; },
      async requireActiveAccessToken() { return token; },
      async issueTokens(params: unknown) { issued++; return params; },
    } } as unknown as OAuthExtensionGrantHandlerInput;
  return { env, args, body, token, issued: () => issued, audited: () => audited,
    setAccount(value: typeof account) { account = value; }, setClient(value: typeof client) { client = value; } };
}

describe("token exchange grant", () => {
  test("audits and issues only narrowed, session-bound tokens", async () => {
    const f = fixture();
    // A properly typed RFC 9068 access-token JWT (typ at+jwt, ES256, kid) is
    // an acceptable subject; the provider verifies signature and session.
    f.body.subject_token = `${btoa(JSON.stringify({ typ: "at+jwt", alg: "ES256", kid: "key" }))}.payload.signature`;
    const result = await handleTokenExchange(f.env, f.args) as unknown as { scopes: string[]; resources: string[]; sessionId: string; tokenResponse: { issued_token_type: string } };
    expect(result.scopes).toEqual(["read"]);
    expect(result.resources).toEqual(["https://api.example.test/"]);
    expect(result.sessionId).toBe("session-a");
    expect(result.tokenResponse.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
    expect(f.audited()).toBe(1);
    expect(f.issued()).toBe(1);
  });
  test("denies missing allowlist, public clients, invalid tokens and privilege escalation", async () => {
    for (const mutate of [
      (f: ReturnType<typeof fixture>) => { f.env.TOKEN_EXCHANGE_ALLOWED_RESOURCES = undefined; },
      (f: ReturnType<typeof fixture>) => f.setClient({ clientId: "client-a", tokenEndpointAuthMethod: "none" }),
      (f: ReturnType<typeof fixture>) => { f.token.active = false; },
      (f: ReturnType<typeof fixture>) => { f.token.client_id = "other"; },
      (f: ReturnType<typeof fixture>) => { f.token.sid = undefined; },
      (f: ReturnType<typeof fixture>) => { f.token.exp = Math.floor(Date.now() / 1000) + 304; },
      (f: ReturnType<typeof fixture>) => { f.token.exp = Math.floor(Date.now() / 1000) + 290; },
      (f: ReturnType<typeof fixture>) => { f.body.resource = "https://other.example.test/"; },
      (f: ReturnType<typeof fixture>) => { f.body.requested_token_type = "urn:ietf:params:oauth:token-type:refresh_token"; },
      (f: ReturnType<typeof fixture>) => { f.token.cnf = { jkt: "key" }; },
      (f: ReturnType<typeof fixture>) => { f.body.scope = "admin" as unknown as string; },
      (f: ReturnType<typeof fixture>) => { f.body.subject_token = "jwt.header.signature"; },
      // ID-token typ must not pass the access-token requirement.
      (f: ReturnType<typeof fixture>) => { f.body.subject_token = `${btoa(JSON.stringify({ typ: ".jwt", alg: "ES256", kid: "key" }))}.payload.signature`; },
      (f: ReturnType<typeof fixture>) => { f.body.subject_token = `${btoa(JSON.stringify({ typ: "at+jwt", alg: "RS256", kid: "key" }))}.payload.signature`; },
      (f: ReturnType<typeof fixture>) => { f.body.actor_token = "unsupported"; },
      (f: ReturnType<typeof fixture>) => f.setAccount({ banned: 1 }),
      (f: ReturnType<typeof fixture>) => f.setAccount(null),
    ]) {
      const f = fixture(); mutate(f);
      await expect(handleTokenExchange(f.env, f.args)).rejects.toThrow();
      expect(f.issued()).toBe(0);
    }
  });
  test("denies issuance if audit storage fails", async () => {
    const f = fixture();
    const db = f.env.DB as unknown as { prepare: (sql: string) => unknown };
    const prepare = db.prepare;
    db.prepare = (sql) => sql.includes("audit_events") ? { bind() { return this; }, async run() { throw new Error("unavailable"); } } : prepare(sql);
    await expect(handleTokenExchange(f.env, f.args)).rejects.toThrow();
    expect(f.issued()).toBe(0);
  });
  test("does not drop authenticated client sender constraints", async () => {
    const f = fixture();
    const provider = f.args.provider;
    const authenticate = provider.authenticateClient;
    provider.authenticateClient = async (request) => ({ ...await authenticate(request), confirmation: { jkt: "key" } });
    await expect(handleTokenExchange(f.env, f.args)).rejects.toThrow();
    expect(f.issued()).toBe(0);
  });
  test("denies unexpected banned representations", async () => {
    const f = fixture();
    f.setAccount({ banned: true } as unknown as { banned: number });
    await expect(handleTokenExchange(f.env, f.args)).rejects.toThrow();
    expect(f.issued()).toBe(0);
  });
});
