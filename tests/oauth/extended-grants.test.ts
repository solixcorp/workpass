import { describe, expect, test } from "bun:test";
import type { OAuthExtensionGrantHandlerInput } from "@better-auth/oauth-provider";
import type { Env } from "../../src/env";
import { handleDeviceCodeGrant, handleCibaGrant } from "../../src/oauth/extended-grants";
import { createDeviceGrant, decideDeviceGrant } from "../../src/oauth/device-flow";
import { createCibaRequest, decideCibaRequest, sha256Hex } from "../../src/oauth/ciba";
import { ensureApplicationTables } from "../../src/db/schema";
import { createTestD1 } from "../test-d1";

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";

async function fixture(options: { deviceFlow: boolean; ciba: boolean }) {
  const testD1 = createTestD1();
  const env = {
    ENABLE_DEVICE_FLOW: options.deviceFlow ? "true" : undefined,
    ENABLE_CIBA: options.ciba ? "true" : undefined,
    DB: testD1.db,
    AUTH_BASE_URL: "https://auth.example.test",
  } as unknown as Env;
  await ensureApplicationTables(env);
  await env.DB.prepare("INSERT INTO applications (id, slug, name, protocol, binding, enabled, created_by, created_at, updated_at) VALUES ('app-cli-1', 'app-cli-1', 'CLI', 'oidc', 'cli-1', 1, 'test', '2026-01-01', '2026-01-01')").run();
  // The grant handlers re-check the user's ban state at the token moment.
  await env.DB.prepare(
    'CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY NOT NULL, email TEXT, username TEXT, banned INTEGER, role TEXT)',
  ).run();
  await env.DB.prepare('INSERT INTO "user" (id, banned) VALUES (\'u1\', 0)').run();
  await env.DB.prepare('INSERT INTO "user" (id, banned) VALUES (\'u2\', 0)').run();
  await env.DB.prepare('CREATE TABLE "session" (id TEXT PRIMARY KEY, token TEXT, "userId" TEXT, "expiresAt" INTEGER)').run();
  for (const id of ["sess-1", "sess-7", "sess-9"]) {
    await env.DB.prepare('INSERT INTO "session" VALUES (?, ?, ?, ?)').bind(id, `token-${id}`, "u1", Date.now() + 600_000).run();
  }
  let issued = 0;
  let issuedParams: Record<string, unknown> | null = null;
  let client: Record<string, unknown> = {
    clientId: "cli-1", grantTypes: [DEVICE_GRANT, CIBA_GRANT_TYPE], tokenEndpointAuthMethod: "none",
  };
  const makeArgs = (body: Record<string, unknown>) => ({
    ctx: {
      body,
      context: { internalAdapter: { async findUserById() { return { id: "u1" }; } },
        adapter: { async findOne() { return { tokenEndpointAuthMethod: "none" }; } } },
    },
    opts: {},
    provider: {
      async authenticateClient() { return { client, clientId: client.clientId as string }; },
      async issueTokens(params: Record<string, unknown>) {
        issued++; issuedParams = params; return params;
      },
    },
  } as unknown as OAuthExtensionGrantHandlerInput);
  return {
    env, client, makeArgs,
    issued: () => issued, issuedParams: () => issuedParams,
    /** The banned flag lives in the store (handlers re-check at token time). */
    async setBanned(value: number) {
      await env.DB.prepare('UPDATE "user" SET banned = ? WHERE id = \'u1\'').bind(value).run();
    },
    /** Simulate an elapsed poll interval (poll guards compare wall-clock). */
    async elapsePollInterval() {
      await env.DB.prepare("UPDATE oauth_device_grants SET last_poll_at = 0").run();
      await env.DB.prepare("UPDATE oauth_ciba_requests SET last_poll_at = 0").run();
    },
    setClient(value: typeof client) { client = value; },
  };
}

/** Await a rejected grant handler and surface its RFC error code. */
async function rejectsError(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "no-rejection";
  } catch (error) {
    return (error as { body?: { error?: string } })?.body?.error ?? "unknown-error";
  }
}

describe("device code grant", () => {
  test("issues tokens exactly once for an approved grant", async () => {
    const f = await fixture({ deviceFlow: true, ciba: true });
    const grant = await createDeviceGrant(f.env, "cli-1", ["openid", "email"]);
    await decideDeviceGrant(f.env, grant.userCode, true, "u1", "sess-9");
    const args = f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1" });
    const result = await handleDeviceCodeGrant(f.env, args) as unknown as { scopes: string[]; sessionId: string };
    expect(result.scopes).toEqual(["openid", "email"]);
    expect(result.sessionId).toBe("sess-9");
    expect(f.issued()).toBe(1);
    // A fast second poll surfaces slow_down before the single-use check…
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1" })))).toBe("slow_down");
    // …but once the interval has elapsed the grant is spent: nothing issues.
    await f.elapsePollInterval();
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1" })))).toBe("invalid_grant");
    expect(f.issued()).toBe(1);
  });

  test("reports the RFC 8628 lifecycle errors", async () => {
    const f = await fixture({ deviceFlow: true, ciba: true });
    // Pending → authorization_pending; the write also arms the poll clock.
    const grant = await createDeviceGrant(f.env, "cli-1", ["openid"]);
    const args = () => f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1" });
    expect(await rejectsError(handleDeviceCodeGrant(f.env, args()))).toBe("authorization_pending");
    // Polling faster than the interval → slow_down.
    expect(await rejectsError(handleDeviceCodeGrant(f.env, args()))).toBe("slow_down");
    // Denied → access_denied.
    const denied = await createDeviceGrant(f.env, "cli-1", ["openid"]);
    await decideDeviceGrant(f.env, denied.userCode, false, "u1", "sess-1");
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: denied.deviceCode, client_id: "cli-1" })))).toBe("access_denied");
    // Unknown codes are invalid; banned users never receive tokens.
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: "unknown-device-code", client_id: "cli-1" })))).toBe("invalid_grant");
    const approved = await createDeviceGrant(f.env, "cli-1", ["openid"]);
    await decideDeviceGrant(f.env, approved.userCode, true, "u1", "sess-1");
    f.setClient({ clientId: "cli-1", grantTypes: [DEVICE_GRANT], tokenEndpointAuthMethod: "none" });
    await f.setBanned(1);
    await f.elapsePollInterval();
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: approved.deviceCode, client_id: "cli-1" })))).toBe("invalid_grant");
    expect(f.issued()).toBe(0);
  });

  test("requires the right client, the registered grant, and the flag", async () => {
    const f = await fixture({ deviceFlow: true, ciba: true });
    const grant = await createDeviceGrant(f.env, "cli-1", ["openid"]);
    await decideDeviceGrant(f.env, grant.userCode, true, "u1", "sess-1");
    // A different client cannot redeem another client's grant.
    f.setClient({ clientId: "cli-2", grantTypes: [DEVICE_GRANT], tokenEndpointAuthMethod: "none" });
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-2" })))).toBe("invalid_grant");
    // A client not registered for the grant is unauthorized.
    f.setClient({ clientId: "cli-2", grantTypes: ["authorization_code"], tokenEndpointAuthMethod: "none" });
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-2" })))).toBe("unauthorized_client");
    // The flag closes the grant even for a registered client.
    const closed = await fixture({ deviceFlow: false, ciba: true });
    f.setClient({ clientId: "cli-1", grantTypes: [DEVICE_GRANT], tokenEndpointAuthMethod: "none" });
    expect(await rejectsError(handleDeviceCodeGrant(closed.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1" })))).toBe("unauthorized_client");
    // Unexpected request fields are invalid_request.
    f.setClient({ clientId: "cli-1", grantTypes: [DEVICE_GRANT], tokenEndpointAuthMethod: "none" });
    expect(await rejectsError(handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1", resource: "https://x/" })))).toBe("invalid_request");
    expect(f.issued()).toBe(0);
  });
});

describe("ciba token grant", () => {
  test("issues once after approval; confidential clients only", async () => {
    const f = await fixture({ deviceFlow: true, ciba: true });
    const request = await createCibaRequest(f.env, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "cli login" });
    const approved = await decideCibaRequest(f.env, await sha256Hex(request.authReqId), "u1", true, "sess-7");
    expect(approved).toBe(true);
    f.setClient({ clientId: "cli-1", grantTypes: [CIBA_GRANT_TYPE], tokenEndpointAuthMethod: "client_secret_basic" });
    const result = await handleCibaGrant(f.env, f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: request.authReqId })) as unknown as { sessionId: string };
    expect(result.sessionId).toBe("sess-7");
    expect(f.issued()).toBe(1);
    // Single-use: after the interval, the spent request is invalid.
    await f.elapsePollInterval();
    expect(await rejectsError(handleCibaGrant(f.env, f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: request.authReqId })))).toBe("invalid_grant");
    // Public clients are not a CIBA surface, even with a pending approval.
    const pending = await createCibaRequest(f.env, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "" });
    f.setClient({ clientId: "cli-1", grantTypes: [CIBA_GRANT_TYPE], tokenEndpointAuthMethod: "none" });
    expect(await rejectsError(handleCibaGrant(f.env, f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: pending.authReqId })))).toBe("unauthorized_client");
    expect(f.issued()).toBe(1);
  });

  test("fails closed around the flag, pending state, and ownership", async () => {
    const f = await fixture({ deviceFlow: true, ciba: true });
    f.setClient({ clientId: "cli-1", grantTypes: [CIBA_GRANT_TYPE], tokenEndpointAuthMethod: "client_secret_basic" });
    const request = await createCibaRequest(f.env, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "" });
    const args = () => f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: request.authReqId });
    // Still pending → authorization_pending.
    expect(await rejectsError(handleCibaGrant(f.env, args()))).toBe("authorization_pending");
    // Another client's request never resolves for this client.
    const other = await createCibaRequest(f.env, { clientId: "cli-2", userId: "u2", scopes: ["openid"], bindingMessage: "" });
    f.setClient({ clientId: "cli-1", grantTypes: [CIBA_GRANT_TYPE], tokenEndpointAuthMethod: "client_secret_basic" });
    expect(await rejectsError(handleCibaGrant(f.env, f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: other.authReqId })))).toBe("invalid_grant");
    // Flag off → unauthorized_client.
    const closed = await fixture({ deviceFlow: true, ciba: false });
    expect(await rejectsError(handleCibaGrant(closed.env, args()))).toBe("unauthorized_client");
    // Malformed bodies are invalid requests.
    expect(await rejectsError(handleCibaGrant(f.env, f.makeArgs({ grant_type: CIBA_GRANT_TYPE })))).toBe("invalid_request");
    expect(await rejectsError(handleCibaGrant(f.env, f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: request.authReqId, resource: "https://x/" })))).toBe("invalid_request");
    expect(f.issued()).toBe(0);
  });
});

for (const kind of ["device", "ciba"] as const) {
  test(`${kind} rechecks session MFA at redemption`, async () => {
    for (const proof of [false, true]) {
      const f = await fixture({ deviceFlow: true, ciba: true });
      f.env.MFA_REQUIRE = "everyone";
      if (proof) await f.env.DB.prepare(
        'INSERT INTO session_mfa_proofs (session_token, user_id, verified_at, methods) VALUES (?, ?, ?, ?)',
      ).bind("token-sess-1", "u1", new Date().toISOString(), "totp").run();
      let run: Promise<unknown>;
      if (kind === "device") {
        const grant = await createDeviceGrant(f.env, "cli-1", ["openid"]);
        await decideDeviceGrant(f.env, grant.userCode, true, "u1", "sess-1");
        run = handleDeviceCodeGrant(f.env, f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1" }));
      } else {
        f.setClient({ clientId: "cli-1", grantTypes: [CIBA_GRANT_TYPE], tokenEndpointAuthMethod: "client_secret_basic" });
        const grant = await createCibaRequest(f.env, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "" });
        await decideCibaRequest(f.env, await sha256Hex(grant.authReqId), "u1", true, "sess-1");
        run = handleCibaGrant(f.env, f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: grant.authReqId }));
      }
      if (proof) await run;
      else {
        expect(await rejectsError(run)).toBe("access_denied");
        const table = kind === "device" ? "oauth_device_grants" : "oauth_ciba_requests";
        expect(await f.env.DB.prepare(`SELECT status FROM ${table}`).first("status")).toBe("approved");
      }
      expect(f.issued()).toBe(proof ? 1 : 0);
    }
  });
  test(`${kind} fails closed when policy storage is unavailable`, async () => {
    const f = await fixture({ deviceFlow: true, ciba: true });
    let args: OAuthExtensionGrantHandlerInput;
    if (kind === "device") {
      const grant = await createDeviceGrant(f.env, "cli-1", ["openid"]);
      await decideDeviceGrant(f.env, grant.userCode, true, "u1", "sess-1");
      args = f.makeArgs({ grant_type: DEVICE_GRANT, device_code: grant.deviceCode, client_id: "cli-1" });
    } else {
      f.setClient({ clientId: "cli-1", grantTypes: [CIBA_GRANT_TYPE], tokenEndpointAuthMethod: "client_secret_basic" });
      const grant = await createCibaRequest(f.env, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "" });
      await decideCibaRequest(f.env, await sha256Hex(grant.authReqId), "u1", true, "sess-1");
      args = f.makeArgs({ grant_type: CIBA_GRANT_TYPE, auth_req_id: grant.authReqId });
    }
    await f.env.DB.prepare("DROP TABLE app_access_policies").run();
    expect(await rejectsError(kind === "device" ? handleDeviceCodeGrant(f.env, args) : handleCibaGrant(f.env, args))).toBe("temporarily_unavailable");
    expect(f.issued()).toBe(0);
    const table = kind === "device" ? "oauth_device_grants" : "oauth_ciba_requests";
    expect(await f.env.DB.prepare(`SELECT status FROM ${table}`).first("status")).toBe("approved");
    // Repair the transient failure, respect the poll interval, and retry the
    // very same grant: policy errors must not burn its single-use capability.
    await ensureApplicationTables(f.env);
    await f.elapsePollInterval();
    await (kind === "device" ? handleDeviceCodeGrant(f.env, args) : handleCibaGrant(f.env, args));
    expect(f.issued()).toBe(1);
    await f.elapsePollInterval();
    expect(await rejectsError(kind === "device" ? handleDeviceCodeGrant(f.env, args) : handleCibaGrant(f.env, args))).toBe("invalid_grant");
    expect(f.issued()).toBe(1);
  });
}
