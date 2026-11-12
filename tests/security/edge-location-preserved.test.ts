import { expect, test } from "bun:test";
import { rebuildRequest, stripUntrustedOAuthQuery } from "../../src/auth/routes";

function withCf(request: Request, cf: Record<string, unknown>): Request {
  Object.defineProperty(request, "cf", { value: cf, enumerable: true });
  return request;
}

const edge = { country: "KR", region: "Seoul", city: "Seoul", latitude: "37.5", longitude: "127.0" };

test("rebuilding a request keeps the edge location", () => {
  const original = withCf(new Request("https://auth.test/api/auth/x", { method: "POST", body: "{}" }), edge);
  const rebuilt = rebuildRequest(original, "https://auth.test/api/auth/y", { method: "POST", body: "{}" });
  expect((rebuilt as Request & { cf?: unknown }).cf).toEqual(edge);
});

test("a request without edge data stays without it", () => {
  const rebuilt = rebuildRequest(new Request("https://auth.test/a"), "https://auth.test/b", {});
  expect((rebuilt as Request & { cf?: unknown }).cf).toBeUndefined();
});

test("stripping the oauth query on a passkey sign-in keeps the location", async () => {
  for (const [method, body, type] of [
    ["POST", JSON.stringify({ response: {} }), "application/json"],
    ["POST", "a=b", "application/x-www-form-urlencoded"],
    ["POST", "plain", "text/plain"],
    ["GET", undefined, undefined],
  ] as const) {
    const original = withCf(new Request("https://auth.test/api/auth/passkey/verify-authentication?oauth_query=x", {
      method, body, headers: type ? { "content-type": type } : undefined,
    }), edge);
    const rebuilt = await stripUntrustedOAuthQuery(original);
    expect(new URL(rebuilt.url).searchParams.has("oauth_query")).toBe(false);
    expect((rebuilt as Request & { cf?: unknown }).cf).toEqual(edge);
  }
});
