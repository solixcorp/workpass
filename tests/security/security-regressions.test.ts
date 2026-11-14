import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { issueSwaGrant } from "../../src/swa/applications";
import { hotpVerify } from "../../src/mfa/hotp";
import { handleTwoFactorVerification } from "../../src/audit/auth-middleware";
import { evaluateOpaqueLoginGate, stepUpOutcome } from "../../src/auth/opaque-login";
import {
  cleanupSessionMfaProofs,
  getSessionMfaProof,
  recordSessionMfaProof,
  sessionSatisfiesRequireMfa,
} from "../../src/mfa/second-factor";
import { enforceOidcPolicy } from "../../src/access/oidc-gate";
import type { AuthInstance } from "../../src/auth/config";

const execution = {} as ExecutionContext;

describe("security regressions", () => {
  test("OPAQUE login endpoints are served and gated", async () => {
    const { default: worker } = await import("../../src/index");
    const env = { AUTH_SECRET: "security-review-secret-0123456789abcdef", AUTH_BASE_URL: "https://idp.test", DB: { prepare: () => ({ all: async () => ({ results: [] }), bind: () => ({ first: async () => null, run: async () => ({ meta: { changes: 0 } }), all: async () => ({ results: [] }) }) }) } } as unknown as Env;
    const headers = { "Content-Type": "application/json", Origin: "https://idp.test" };
    // Registration requires a session; with the bare stub the session
    // lookup itself fails, so only assert the route is mounted (not 404).
    // The real gating behavior is covered by the opaque smoke.
    const register = await worker.fetch(new Request("https://idp.test/api/opaque/register/start", { method: "POST", headers }), env, execution);
    expect(register.status).not.toBe(404);
    // Malformed login start rejects without issuing anything.
    const start = await worker.fetch(new Request("https://idp.test/api/opaque/auth/start", { method: "POST", headers, body: JSON.stringify({}) }), env, execution);
    expect(start.status).toBe(400);
    // Sealed fingerprint results are explicitly rejected (risk contract).
    const sealed = await worker.fetch(new Request("https://idp.test/api/opaque/auth/start", { method: "POST", headers, body: JSON.stringify({ ke1: "abcd", fingerprint: { sealed_result: "x" } }) }), env, execution);
    expect(sealed.status).toBe(400);
    expect((await sealed.text()).includes("Sealed")).toBe(true);
  });

  test("MFA policy honors only session-bound proofs", async () => {
    const proofRow = { userId: "user", verifiedAt: new Date().toISOString() };
    const withProof = { DB: { prepare: (sql: string) => ({ bind: () => ({
      first: async () => sql.includes("FROM session_mfa_proofs") ? proofRow : null,
    }) }) } } as unknown as Env;
    const withoutProof = { DB: { prepare: () => ({ bind: () => ({ first: async () => null }) }) } } as unknown as Env;
    const session = { user: { id: "user" }, session: { token: "tok" } };
    expect(await sessionSatisfiesRequireMfa(withoutProof, session)).toBe(false);
    expect(await sessionSatisfiesRequireMfa(withProof, session)).toBe(true);
    // A proof belongs to one user only.
    expect(await sessionSatisfiesRequireMfa(withProof, { user: { id: "other" }, session: { token: "tok" } })).toBe(false);
    // A session without a readable token can never satisfy the policy.
    expect(await sessionSatisfiesRequireMfa(withProof, { user: { id: "user" }, session: { token: 42 } })).toBe(false);
  });

  test("proof recording persists the session binding and rejects bad material", async () => {
    const seen: Array<{ token: unknown; user: unknown; at: unknown }> = [];
    const env = { DB: { prepare: (sql: string) => ({ bind: (...args: unknown[]) => ({
      run: async () => {
        if (sql.includes("INSERT INTO session_mfa_proofs")) {
          seen.push({ token: args[0], user: args[1], at: args[2] });
          return { meta: { changes: 1 } };
        }
        throw new Error("unexpected sql");
      },
    }) }) } } as unknown as Env;
    expect(await recordSessionMfaProof(env, "tok", "user")).toBe(true);
    expect(seen).toHaveLength(1);
    expect(seen[0].token).toBe("tok");
    expect(seen[0].user).toBe("user");
    expect(typeof seen[0].at).toBe("string");
    expect(await recordSessionMfaProof(env, "x".repeat(600), "user")).toBe(false);
    expect(await recordSessionMfaProof(env, "tok", "")).toBe(false);
  });

  test("proof lookup returns the stored record", async () => {
    const env = { DB: { prepare: (sql: string) => ({ bind: () => ({
      first: async () => sql.includes("FROM session_mfa_proofs") ? { userId: "user", verifiedAt: "2026-11-09T00:00:00.000Z" } : null,
    }) }) } } as unknown as Env;
    const proof = await getSessionMfaProof(env, "tok");
    expect(proof?.userId).toBe("user");
  });

  test("proof cleanup deletes expired rows and skips missing tables", async () => {
    let deleted = false;
    const present = { DB: { prepare: (sql: string) => ({
      first: async () => sql.includes("sqlite_master") ? { name: "session_mfa_proofs" } : null,
      bind: () => ({ run: async () => { if (sql.includes("DELETE FROM session_mfa_proofs")) deleted = true; return { meta: { changes: 1 } }; } }),
    }) } } as unknown as Env;
    const absent = { DB: { prepare: (sql: string) => ({
      first: async () => null,
      bind: () => ({ run: async () => { deleted = true; return { meta: { changes: 1 } }; } }),
    }) } } as unknown as Env;
    await cleanupSessionMfaProofs(present);
    expect(deleted).toBe(true);
    deleted = false;
    await cleanupSessionMfaProofs(absent);
    expect(deleted).toBe(false);
  });

  test("SWA grant defaults to five minutes", async () => {
    const env = { DB: { prepare: () => ({ bind: () => ({ run: async () => ({ meta: { changes: 1 } }) }) }) } } as unknown as Env;
    const start = Date.now();
    const grant = await issueSwaGrant(env, { applicationId: "app", userId: "user" });
    expect(Date.parse(grant.expiresAt) - start).toBeGreaterThanOrEqual(300_000);
    expect(Date.parse(grant.expiresAt) - start).toBeLessThan(301_000);
  });

  test("HOTP accepts only one concurrent use of a code", async () => {
    let counter = 0;
    const env = { DB: { prepare: (sql: string) => ({ bind: (...args: unknown[]) => ({
      all: async () => ({ results: [{ id: "token", secretB32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", counter: 0 }] }),
      run: async () => {
        if (sql.includes("AND counter = ?")) {
          if (counter !== args[3]) return { meta: { changes: 0 } };
          counter = args[0] as number;
          return { meta: { changes: 1 } };
        }
        throw new Error("unexpected update");
      },
    }) }) } } as unknown as Env;
    const results = await Promise.all([hotpVerify(env, "user", "755224"), hotpVerify(env, "user", "755224")]);
    expect(results.filter((r) => r.verified)).toHaveLength(1);
  });

  test("OIDC policy lookup fails closed and direct unsigned continuation is rejected", async () => {
    const auth = { api: { getSession: async () => ({ user: { id: "user" } }) } } as unknown as AuthInstance;
    const env = { AUTH_SECRET: "a".repeat(32), DB: { prepare: () => { throw new Error("unavailable"); } } } as unknown as Env;
    const get = new Request("https://idp.test/api/auth/oauth2/authorize?client_id=client");
    expect((await enforceOidcPolicy(get, env, auth))?.status).toBe(503);
    const post = new Request("https://idp.test/api/auth/oauth2/consent", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ oauth_query: "client_id=client" }) });
    expect((await enforceOidcPolicy(post, env, auth))?.status).toBe(400);
  });

  test("OIDC enforces group and MFA policy on authorization", async () => {
    const auth = { api: { getSession: async () => ({ user: { id: "user" }, session: { token: "tok" } }) } } as unknown as AuthInstance;
    let requireMfa = 0;
    let member = 0;
    let proof: { userId: string; verifiedAt: string } | null = null;
    const env = { DB: { prepare: (sql: string) => ({ bind: () => ({
      first: async () => sql.includes("FROM app_access_policies")
        ? { subject: "oidc:client", allowedMethods: "password,passkey", sessionTtlSeconds: null, bypassWindowSeconds: 0, enforcementMode: "enforce", requireMfa }
        : sql.includes("FROM session_mfa_proofs")
          ? proof
          : sql.includes("FROM app_temporal_grants")
            ? null
            : { count: member },
      all: async () => ({ results: [{ group_id: "group" }] }),
    }) }) } } as unknown as Env;
    const request = new Request("https://idp.test/api/auth/oauth2/authorize?client_id=client");
    // Group gate denies first.
    expect((await enforceOidcPolicy(request, env, auth))?.status).toBe(403);
    member = 1;
    expect(await enforceOidcPolicy(request, env, auth)).toBeNull();
    // With requireMfa, only a verified session proof passes.
    requireMfa = 1;
    expect((await enforceOidcPolicy(request, env, auth))?.status).toBe(403);
    proof = { userId: "user", verifiedAt: new Date().toISOString() };
    expect(await enforceOidcPolicy(request, env, auth)).toBeNull();
    // A proof bound to another user does not transfer.
    proof = { userId: "other", verifiedAt: new Date().toISOString() };
    expect((await enforceOidcPolicy(request, env, auth))?.status).toBe(403);
  });

  // Regression: the plugin ROTATES the session on the first verify-totp (new
  // cookie + old session row deleted) while the JSON body still echoes the
  // rotated-out token. The proof must bind to the token that is actually
  // alive after the verification.
  test("two-factor verification records the rotated-in session, not the echoed token", async () => {
    const recordedProofs: Array<[string, string]> = [];
    let sessionRowTokens: string[] = ["new-token"];
    const env = { DB: { prepare: (sql: string) => ({ bind: (...args: unknown[]) => ({
      first: async () => {
        if (sql.includes('FROM "session"')) {
          const token = args[0] as string;
          if (sessionRowTokens.includes(token)) return { token, userId: "u1" };
          return null;
        }
        return null;
      },
      run: async () => {
        if (sql.includes("INSERT INTO session_mfa_proofs")) {
          recordedProofs.push([args[0] as string, args[1] as string]);
          return { meta: { changes: 1 } };
        }
        return { meta: { changes: 0 } };
      },
    }) }) } } as unknown as Env;
    const verifyRequest = new Request("https://idp.test/api/auth/two-factor/verify-totp", { method: "POST" });

    // Case 1: rotation — response cookie carries the NEW session, the body
    // carries the rotated-out one, which was already deleted.
    const rotated = await handleTwoFactorVerification(verifyRequest.clone(), env, {
      handler: async () => {
        const response = Response.json({ token: "old-token", user: { id: "u1" } });
        response.headers.append("set-cookie", 'better-auth.session_token=new-token.sig; Path=/; HttpOnly; SameSite=Lax');
        return response;
      },
    } as unknown as AuthInstance);
    expect(rotated.status).toBe(200);
    // The old token no longer exists in the session table (deleted on rotation).
    expect(recordedProofs).toEqual([["new-token", "u1"]]);

    // Case 2: no rotation (later verifications) — the body token is live.
    recordedProofs.length = 0;
    sessionRowTokens = ["live-token"];
    const plain = await handleTwoFactorVerification(verifyRequest.clone(), env, {
      handler: async () => Response.json({ token: "live-token", user: { id: "u1" } }),
    } as unknown as AuthInstance);
    expect(plain.status).toBe(200);
    expect(recordedProofs).toEqual([["live-token", "u1"]]);

    // Case 3: a token that does not resolve in storage never gets a proof.
    recordedProofs.length = 0;
    sessionRowTokens = [];
    const ghost = await handleTwoFactorVerification(verifyRequest.clone(), env, {
      handler: async () => Response.json({ token: "ghost-token" }),
    } as unknown as AuthInstance);
    expect(ghost.status).toBe(503);
    expect(recordedProofs).toEqual([]);
  });

  // Regression: OPAQUE login re-enabled is gated by account state and the
  // shared device-risk pipeline before any session issues.
  test("OPAQUE login gate denies banned accounts and fails closed", async () => {
    let bannedValue: unknown = 1;
    const env = { DB: { prepare: (sql: string) => ({ bind: () => ({
      first: async () => {
        if (sql.includes('banned FROM "user"')) {
          if (bannedValue === "throw") throw new Error("db unavailable");
          return bannedValue === "missing" ? null : { banned: bannedValue };
        }
        return null;
      },
    }) }) } } as unknown as Env;
    const input = { userId: "u1", eventId: null, request: new Request("https://idp.test/api/opaque/auth/finish", { method: "POST" }), contextPath: "/api/opaque/auth/finish" };
    const banned = await evaluateOpaqueLoginGate(env, input);
    expect(banned.allowed).toBe(false);
    expect(banned.reasons).toContain("account_disabled");
    // A missing account row denies as well (fail closed), never a silent pass.
    bannedValue = "missing";
    expect((await evaluateOpaqueLoginGate(env, input)).allowed).toBe(false);
    // Unreadable storage denies too.
    bannedValue = "throw";
    const failed = await evaluateOpaqueLoginGate(env, input);
    expect(failed.allowed).toBe(false);
    expect(failed.reasons).toContain("account_unavailable");
  });

  test("OPAQUE login gate always assesses the device once the server key exists", async () => {
    const input = { userId: "u1", eventId: null, request: new Request("https://idp.test/api/opaque/auth/finish", { method: "POST" }), contextPath: "/api/opaque/auth/finish" };
    const db = (decisions: string[]) => ({ prepare: (sql: string) => ({ bind: () => ({
      first: async () => sql.includes('banned FROM "user"') ? { banned: 0 } : null,
      run: async () => { if (sql.includes("INSERT INTO fingerprint_risk_decisions")) decisions.push(sql); return { meta: { changes: 1 } }; },
    }) }) });
    // No server key: there is nothing to assess with.
    expect((await evaluateOpaqueLoginGate({ DB: db([]) } as unknown as Env, input)).allowed).toBe(true);
    // Server key present, blocking off (the default): the gap is recorded and sign-in goes on.
    const observed: string[] = [];
    const passed = await evaluateOpaqueLoginGate({ FINGERPRINT_SERVER_API_KEY: "key", DB: db(observed) } as unknown as Env, input);
    expect(passed.allowed).toBe(true);
    expect(passed.reasons).toContain("missing_event");
    expect(observed.length).toBeGreaterThan(0);
    // Blocking on: a login without a submitted event is denied and recorded.
    const decisions: string[] = [];
    const denied = await evaluateOpaqueLoginGate({ FINGERPRINT_SERVER_API_KEY: "key", FINGERPRINT_BLOCK_SIGN_IN: "true", DB: db(decisions) } as unknown as Env, input);
    expect(denied.allowed).toBe(false);
    expect(denied.action).toBe("deny");
    expect(denied.reasons).toContain("missing_event");
    expect(decisions.length).toBeGreaterThan(0);
    // Break-glass is the only way to turn it off.
    expect((await evaluateOpaqueLoginGate({ FINGERPRINT_SERVER_API_KEY: "key", FINGERPRINT_BREAK_GLASS: "true", DB: db([]) } as unknown as Env, input)).allowed).toBe(true);
  });

  test("a new device alone does not lock out an account that has no second factor, but a stronger signal still does", async () => {
    const env = { DB: { prepare: () => ({ bind: () => ({ all: async () => ({ results: [] }), first: async () => null }) }) } } as unknown as Env;
    const fresh = await stepUpOutcome(env, "u1", ["untrusted_device", "incognito_detected"]);
    expect(fresh).toMatchObject({ allowed: true, action: "allow" });
    const vm = await stepUpOutcome(env, "u1", ["virtual_machine_detected"]);
    expect(vm).toMatchObject({ allowed: false, action: "deny" });
    expect(vm.reasons).toContain("no_second_factor");
    const mixed = await stepUpOutcome(env, "u1", ["untrusted_device", "rapid_device_and_country_change"]);
    expect(mixed.allowed).toBe(false);
  });
});
