import { afterEach, describe, expect, spyOn, test } from "bun:test";
import type { Env } from "../../src/env";
import * as authConfig from "../../src/auth/config";
import { ensureApplicationTables } from "../../src/db/schema";
import { deviceFlowRoutes } from "../../src/oauth/device-routes";
import { cibaRoutes } from "../../src/oauth/ciba-routes";
import { createDeviceGrant, loadDeviceGrantByCode } from "../../src/oauth/device-flow";
import { createCibaRequest, loadCibaRequest, sha256Hex } from "../../src/oauth/ciba";
import { createTestD1 } from "../test-d1";

let restoreSession: (() => void) | undefined;
afterEach(() => { restoreSession?.(); restoreSession = undefined; });

async function fixture(kind: "device" | "ciba", proof = true) {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_BASE_URL: "https://auth.example.test", ENABLE_DEVICE_FLOW: "true",
    ENABLE_CIBA: "true", MFA_REQUIRE: "everyone" } as unknown as Env;
  await ensureApplicationTables(env);
  await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, enabled, created_by, created_at, updated_at) VALUES ('app-cli-1', 'app-cli-1', 'CLI', 'oidc', 'cli-1', 1, 'test', '2026-01-01', '2026-01-01')").run();
  await db.prepare('CREATE TABLE "user" (id TEXT PRIMARY KEY, role TEXT, banned INTEGER)').run();
  await db.prepare('INSERT INTO "user" VALUES (\'u1\', \'user\', 0)').run();
  if (proof) await db.prepare(
    "INSERT INTO session_mfa_proofs (session_token, user_id, verified_at, methods) VALUES (?, ?, ?, ?)",
  ).bind("session-token", "u1", new Date().toISOString(), "totp").run();
  // Stub authentication only; route parsing, policy/MFA checks, conditional
  // approval writes, and audit writes all run against the real in-memory store.
  const mock = spyOn(authConfig, "createAuth").mockReturnValue({ api: {
    async getSession() { return { user: { id: "u1", role: "user" }, session: { id: "sess-1", token: "session-token" } }; },
  } } as unknown as ReturnType<typeof authConfig.createAuth>);
  restoreSession = () => mock.mockRestore();
  let body: Record<string, string>;
  let state: () => Promise<{ status: string; userId: string | null; sessionId: string | null } | null>;
  if (kind === "device") {
    const grant = await createDeviceGrant(env, "cli-1", ["openid"]);
    body = { user_code: grant.userCode };
    state = () => loadDeviceGrantByCode(env, grant.deviceCode);
  } else {
    const grant = await createCibaRequest(env, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "" });
    body = { request: await sha256Hex(grant.authReqId), decision: "approve" };
    state = () => loadCibaRequest(env, grant.authReqId);
  }
  const call = (override: Record<string, string> = {}) => {
    const routes = kind === "device" ? deviceFlowRoutes : cibaRoutes;
    return routes.request(kind === "device" ? "/api/device/flow/approve" : "/api/ciba/decide", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...body, ...override }),
    }, env);
  };
  return { env, body, call, state };
}

for (const kind of ["device", "ciba"] as const) {
  describe(`${kind} approval route`, () => {
    test("approves an allowed user with session MFA, but cannot decide twice", async () => {
      const f = await fixture(kind);
      const response = await f.call();
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ status: "approved" });
      expect(await f.state()).toMatchObject({ status: "approved", userId: "u1", sessionId: "sess-1" });
      const again = await f.call();
      expect(again.status).toBe(409);
      expect(await again.json()).toMatchObject({ error: "invalid_request" });
      expect((await f.state())?.status).toBe("approved");
    });

    test("rejects missing MFA without approving the grant", async () => {
      const f = await fixture(kind, false);
      const response = await f.call();
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ error: "access_denied", reason: "mfa_required" });
      expect(await f.state()).toMatchObject({ status: "pending", sessionId: null });
    });

    test("policy evaluation failure is clear and leaves approval retryable", async () => {
      const f = await fixture(kind);
      await f.env.DB.prepare("DROP TABLE app_access_policies").run();
      const response = await f.call();
      expect(response.status).toBe(503);
      const error = await response.json() as { error: string; error_description?: string };
      expect(error.error_description ?? error.error).toBe("Authorization policy unavailable");
      expect(await f.state()).toMatchObject({ status: "pending", sessionId: null });
      await ensureApplicationTables(f.env);
      expect((await f.call()).status).toBe(200);
      expect((await f.state())?.status).toBe("approved");
    });

    test("rejects unknown approval identifiers without changing a pending grant", async () => {
      const f = await fixture(kind);
      const response = await f.call(kind === "device" ? { user_code: "XXXX-XXXX" } : { request: "0".repeat(64) });
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
      expect((await f.state())?.status).toBe("pending");
    });

    if (kind === "ciba") test("rejects another user's request", async () => {
      const f = await fixture(kind);
      const other = await createCibaRequest(f.env, { clientId: "cli-1", userId: "u2", scopes: ["openid"], bindingMessage: "" });
      const response = await f.call({ request: await sha256Hex(other.authReqId) });
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
      expect(await loadCibaRequest(f.env, other.authReqId)).toMatchObject({ status: "pending", userId: "u2", sessionId: null });
      expect((await f.state())?.status).toBe("pending");
    });
  });
}
