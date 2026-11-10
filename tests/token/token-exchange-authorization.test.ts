import { describe, expect, test } from "bun:test";
import { authorizeExchange, type ExchangeAuthorizationInput } from "../../src/token/exchange-authorization";

function input(): ExchangeAuthorizationInput {
  return { clientId: "client-a", resource: "https://api.example.test/", nowSeconds: 1000, outputLifetimeSeconds: 300,
    subject: { active: true, clientId: "client-a", userId: "user-a", expiresAt: 1300,
      scopes: "read write", audience: "https://api.example.test/" } };
}

describe("token exchange least-privilege authorization", () => {
  test("allows a scope subset for the same client and resource", () => {
    expect(authorizeExchange({ ...input(), requestedScopes: "read" })).toEqual({ userId: "user-a", scopes: ["read"] });
  });
  test("allows audience delegation but rejects privilege escalation", () => {
    // RFC 8693 audience restriction: the target allowlist is enforced by the caller.
    expect(authorizeExchange({ ...input(), resource: "https://other.example.test/" })).toEqual({ userId: "user-a", scopes: ["read", "write"] });
    expect(authorizeExchange({ ...input(), requestedScopes: "admin" })).toBeNull();
  });
  test("rejects inactive, foreign-client and sender-constrained tokens", () => {
    for (const subject of [
      { ...input().subject, active: false }, { ...input().subject, clientId: "other" },
      { ...input().subject, confirmation: { jkt: "key" } },
    ]) expect(authorizeExchange({ ...input(), subject })).toBeNull();
  });
  test("does not extend source lifetime or create refresh/ID tokens", () => {
    expect(authorizeExchange({ ...input(), subject: { ...input().subject, expiresAt: 1299 } })).toBeNull();
    expect(authorizeExchange({ ...input(), subject: { ...input().subject, scopes: "read offline_access" } })).toBeNull();
    expect(authorizeExchange({ ...input(), subject: { ...input().subject, scopes: "read openid" } })).toBeNull();
  });
  test("rejects malformed resource and scope", () => {
    expect(authorizeExchange({ ...input(), resource: "http://api.example.test/" })).toBeNull();
    expect(authorizeExchange({ ...input(), requestedScopes: "read  write" })).toBeNull();
    expect(authorizeExchange({ ...input(), requestedScopes: "read read" })).toBeNull();
  });
});
