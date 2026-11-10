import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { signSet, verifySet, type SetClaims, type StreamTrust } from "../../src/ssf/set";
import { upsertSsfRecipient, dispatchSSFEvent, ensureSsfDispatchTables } from "../../src/ssf/dispatch";

/**
 * End-to-end SSF: an external sender pushes a signed SET to our receiver
 * (signature, pinned keys, per-stream token, atomic dequeue/duplicate), and
 * our sender dispatches a signed SET to a registered recipient with delivery
 * records. Account-affecting processing is intentionally not wired: events
 * are only durably queued.
 */

const EVENT = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
const SE_TYPE = "secevent+jwt";
const STREAM_TOKEN = "stream-shared-secret-0123456789abcdef";
const MGMT_TOKEN = "ssf-mgmt-token-0123456789abcdef01234567";

function receiverEnv(streamRaw: string): Env {
  return {
    DB: createTestD1().db,
    AUTH_SECRET: "integration-test-secret-0123456789abcdef",
    AUTH_BASE_URL: "http://127.0.0.1:8787",
    ENABLE_MIGRATIONS: "true",
    MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_SSF_RECEIVER: "true",
    SSF_MANAGEMENT_TOKEN: MGMT_TOKEN,
    SSF_STREAMS: streamRaw,
    AEAD_SEALING_KEY: btoa("0123456789abcdef0123456789abcdef"),
  } as unknown as Env;
}

function run(request: Request, env: Env): Promise<Response> {
  return mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
}

describe("SSF receiver", () => {
  let pair: CryptoKeyPair;
  const claims: SetClaims = {
    iss: "https://legacy-IdP.example", aud: "internal-auth", jti: "set-1",
    iat: Math.floor(Date.now() / 1000), sub_id: { format: "email", email: "user@example.com" },
    events: { [EVENT]: {} },
  };

  beforeAll(async () => {
    pair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true, ["sign", "verify"],
    ) as unknown as CryptoKeyPair;
    const publicJwk: Record<string, unknown> = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "sender-key", alg: "RS256" };
    const env = receiverEnv(JSON.stringify([{
      id: "legacy-idp", issuer: "https://legacy-IdP.example", audience: "internal-auth",
      jwks: { keys: [publicJwk] }, event_types: [EVENT],
      max_age_seconds: 3600, delivery_token: STREAM_TOKEN,
    }]));
    globals.env = env;
    const migrate = await run(new Request("http://127.0.0.1:8787/_internal/migrate", {
      method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` },
    }), env);
    if (migrate.status !== 200) throw new Error("receiver migrations failed");
    await import("../../src/ssf/inbox").then((m) => m.ensureSsfInboxTable(env.DB));
  });

  const globals = { env: null as unknown as Env };

  function push(token: string, overrides: Partial<Record<string, string>> = {}): Promise<Response> {
    return run(new Request("http://127.0.0.1:8787/api/ssf/receiver/legacy-idp", {
      method: "POST",
      headers: { "Content-Type": "application/secevent+jwt", Authorization: `Bearer ${STREAM_TOKEN}`, ...overrides },
      body: token,
    }), globals.env);
  }

  test("verifies signatures, queues atomically and accepts duplicates", async () => {
    const token = await signSet(claims, "sender-key", pair.privateKey);
    expect((await push(token)).status).toBe(202);
    expect((await push(token)).status).toBe(202);
    const deniedRequest = await run(new Request("http://127.0.0.1:8787/api/ssf/receiver/legacy-idp", {
      method: "POST", headers: { "Content-Type": "application/secevent+jwt", Authorization: "Bearer wrong" }, body: token,
    }), globals.env);
    expect(deniedRequest.status).toBe(401);
    const other = await signSet({ ...claims, aud: "someone-else" }, "sender-key", pair.privateKey);
    expect((await push(other)).status).toBe(400);
    const wrongType = await run(new Request("http://127.0.0.1:8787/api/ssf/receiver/legacy-idp", {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${STREAM_TOKEN}` }, body: token,
    }), globals.env);
    expect(wrongType.status).toBe(415);
    const unknown = await run(new Request("http://127.0.0.1:8787/api/ssf/receiver/missing", {
      method: "POST", headers: { "Content-Type": "application/secevent+jwt", Authorization: `Bearer ${STREAM_TOKEN}` }, body: token,
    }), globals.env);
    expect(unknown.status).toBe(404);
  });

  test("disabled feature is unreachable", async () => {
    const response = await run(new Request("http://127.0.0.1:8787/api/ssf/receiver/legacy-idp", {
      method: "POST", headers: { "Content-Type": "application/secevent+jwt", Authorization: `Bearer ${STREAM_TOKEN}` },
      body: await signSet(claims, "sender-key", pair.privateKey),
    }), { ...globals.env, ENABLE_SSF_RECEIVER: "false" } as unknown as Env);
    expect(response.status).toBe(404);
  });
});

describe("SSF sender", () => {
  const { db, sqlite } = createTestD1();
  const env = {
    DB: db,
    AUTH_SECRET: "integration-test-secret-0123456789abcdef",
    AUTH_BASE_URL: "http://127.0.0.1:8787",
    ENABLE_MIGRATIONS: "true",
    MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_SSF_SENDER: "true",
    SSF_MANAGEMENT_TOKEN: MGMT_TOKEN,
    AEAD_SEALING_KEY: btoa("0123456789abcdef0123456789abcdef"),
  } as unknown as Env;

  let deliveredToken = "";
  let deliveredAuthorization = "";

  beforeAll(async () => {
    const migrate = await run(new Request("http://127.0.0.1:8787/_internal/migrate", {
      method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` },
    }), env);
    expect(migrate.status).toBe(200);
    await ensureSsfDispatchTables(env.DB);
  });

  test("registers a recipient, dispatches a signed SET and records delivery", async () => {
    const register = await run(new Request("http://127.0.0.1:8787/api/ssf/streams", {
      method: "POST", headers: { Authorization: `Bearer ${MGMT_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ id: "downstream-saas", audience: "downstream-saas", endpoint: "https://receiver.example/events", event_types: [EVENT], delivery_token: "shared-0123456789" }),
    }), env);
    expect(register.status).toBe(201);
    const anonymous = await run(new Request("http://127.0.0.1:8787/api/ssf/streams", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: "x", audience: "x", endpoint: "https://r.example/e", event_types: [EVENT] }),
    }), env);
    expect(anonymous.status).toBe(401);

    const send = (async (_url: unknown, init?: RequestInit) => {
      deliveredToken = String(init?.body);
      deliveredAuthorization = String(new Headers(init?.headers).get("Authorization"));
      return new Response(null, { status: 202 });
    }) as unknown as typeof fetch;
    const result = await dispatchSSFEvent(env, {
      recipientId: "downstream-saas",
      eventType: EVENT,
      subject: { format: "email", email: "user@example.com" },
    }, send).catch((error) => ({ error: (error as Error).message }));
    expect(result).toHaveProperty("state", "delivered");
    // A signed three-part SET with the platform kid was delivered.
    expect(deliveredToken.split(".").length).toBe(3);
    expect(deliveredAuthorization).toBe("Bearer shared-0123456789");

    const jwksRoute = await run(new Request("http://127.0.0.1:8787/api/ssf/jwks.json"), env);
    expect(jwksRoute.status).toBe(200);
    const jwks = await jwksRoute.json() as { keys: Record<string, unknown>[] };
    const imported = await crypto.subtle.importKey("jwk", jwks.keys[0] as JsonWebKey, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const trust: StreamTrust = { issuer: "http://127.0.0.1:8787", audience: "downstream-saas",
      keys: new Map([["ssf-1", imported]]), eventTypes: [EVENT], maxAgeSeconds: 3600 };
    const verifiedClaims = await verifySet(deliveredToken, trust);
    expect(verifiedClaims.events[EVENT]).toEqual({});

    const deliveries = sqlite.query("SELECT state, recipient_id FROM ssf_deliveries").all() as { state: string; recipient_id: string }[];
    expect(deliveries).toEqual([{ state: "delivered", recipient_id: "downstream-saas" }]);
  });

  test("unknown recipient and disabled event types are rejected", async () => {
    const send = (async () => new Response(null, { status: 202 })) as unknown as typeof fetch;
    await expect(dispatchSSFEvent(env, { recipientId: "missing", eventType: EVENT, subject: { format: "email" } }, send)).rejects.toThrow("Recipient not found");
    await expect(dispatchSSFEvent(env, { recipientId: "downstream-saas", eventType: "urn:example:unrelated", subject: { format: "email" } }, send)).rejects.toThrow("Event type");
  });
});
