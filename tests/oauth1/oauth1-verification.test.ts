import { describe, expect, test } from "bun:test";
import { oauth1HmacSha1, oauth1SignatureBaseString, oauthPercentEncode } from "../../src/oauth1/signature";
import { verifyOAuth1Request, type OAuth1VerificationOptions } from "../../src/oauth1/verify";

const now = 1700000000;

async function signedRequest(overrides: { url?: string; body?: string; timestamp?: string; signature?: string; token?: string } = {}) {
  const url = overrides.url ?? "https://example.test/request?a=1&a=2";
  const body = overrides.body ?? "b=3";
  const pairs: [string, string][] = [
    ["oauth_consumer_key", "consumer"], ["oauth_nonce", "unique"],
    ["oauth_timestamp", overrides.timestamp ?? String(now)], ["oauth_signature_method", "HMAC-SHA1"],
  ];
  if (overrides.token !== undefined) pairs.push(["oauth_token", overrides.token]);
  const base = oauth1SignatureBaseString("POST", url, [...pairs, ...new URLSearchParams(body)]);
  const signature = overrides.signature ?? await oauth1HmacSha1(base, "secret", overrides.token === undefined ? "" : "token-secret");
  const authorization = "OAuth " + [...pairs, ["oauth_signature", signature]].map(([k, v]) => `${k}="${oauthPercentEncode(v!)}"`).join(", ");
  return new Request(url, { method: "POST", headers: { Authorization: authorization, "Content-Type": "application/x-www-form-urlencoded" }, body });
}

function options(): OAuth1VerificationOptions {
  const seen = new Set<string>();
  return {
    now,
    resolveCredential: async (consumer, token) => consumer === "consumer" && (token === undefined || token === "token") ? { consumerSecret: "secret", tokenSecret: "token-secret" } : null,
    claimNonce: async (consumer, token, timestamp, nonce) => {
      const key = JSON.stringify([consumer, token, timestamp, nonce]);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

describe("OAuth 1 request verification", () => {
  test("accepts a signed request once and rejects replay", async () => {
    const request = await signedRequest({ token: "token" });
    const config = options();
    expect((await verifyOAuth1Request(request, config))?.consumerKey).toBe("consumer");
    expect(await verifyOAuth1Request(request, config)).toBeNull();
    expect(await request.text()).toBe("b=3");
  });

  test("rejects invalid signatures, stale timestamps and mixed parameter sources", async () => {
    for (const input of [
      { signature: "incorrect" }, { timestamp: String(now - 301) },
      { url: "https://example.test/request?oauth_nonce=other" }, { body: "oauth_token=other" },
      { token: "unknown" },
    ]) expect(await verifyOAuth1Request(await signedRequest(input), options())).toBeNull();
  });

  test("never consumes nonces before successful verification and fails closed on store errors", async () => {
    let claims = 0;
    const config = options();
    config.claimNonce = async () => { claims++; throw new Error("unavailable"); };
    expect(await verifyOAuth1Request(await signedRequest({ signature: "bad" }), config)).toBeNull();
    expect(claims).toBe(0);
    expect(await verifyOAuth1Request(await signedRequest(), config)).toBeNull();
    expect(claims).toBe(1);
  });
});
