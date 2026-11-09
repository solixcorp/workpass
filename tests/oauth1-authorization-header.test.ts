import { describe, expect, test } from "bun:test";
import { parseOAuth1AuthorizationHeader } from "../src/oauth1/authorization-header";

describe("OAuth 1 authorization header parser", () => {
  test("decodes OAuth parameters and excludes the unsigned realm", () => {
    expect(parseOAuth1AuthorizationHeader('OAuth realm="example", oauth_consumer_key="a%2Bb", oauth_nonce="x%20y"'))
      .toEqual([["oauth_consumer_key", "a+b"], ["oauth_nonce", "x y"]]);
  });
  test("rejects ambiguous, malformed and duplicate fields", () => {
    for (const header of [
      'Bearer token', 'OAuth ', 'OAuth oauth_nonce="a",', 'OAuth oauth_nonce="a" oauth_token="b"',
      'OAuth oauth_nonce="a", oauth_nonce="b"', 'OAuth oauth_nonce="%ZZ"',
      'OAuth oauth_nonce="a", ordinary="b"', 'OAuth oauth_nonce="a\\"b"',
    ]) expect(() => parseOAuth1AuthorizationHeader(header)).toThrow();
  });
});
