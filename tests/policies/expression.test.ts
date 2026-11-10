/**
 * The expression interpreter (docs/design/authentik-policies.md): language
 * semantics, host isolation, the step budget, and helper behavior. Runs with
 * `bun test tests/policies/expression.test.ts`.
 */

import { describe, expect, test } from "bun:test";
import { evaluateExpression } from "../../src/policies/expression";
import { buildGlobals } from "../../src/policies/helpers";
import type { Env } from "../../src/env";

const evalWith = async (source: string, globals: Record<string, unknown> = {}, budget = 100_000) =>
  (await evaluateExpression(source, () => ({ ...globals }), budget)).value;

const HELPER_ENV = {
  AUTH_BASE_URL: "https://idp.test",
  DB: {
    prepare: () => ({
      bind: () => ({ first: async () => null, all: async () => ({ results: [] }) }),
    }),
  },
} as unknown as Env;

const evalHelpers = async (
  source: string,
  context: Record<string, unknown> = {},
  clientIp: string | null = null,
) => {
  const messages: string[] = [];
  const result = await evaluateExpression(
    source,
    () => buildGlobals(
      { messages, callPolicyByName: async () => ({ passing: false, messages: [], rawResult: null }) },
      HELPER_ENV as Env,
      { user: null, clientIp, subject: null, context, requestPath: "/policies/test" } as never,
    ),
    50_000,
  );
  return { value: result.value, messages };
};

describe("expression language semantics", () => {
  test("operator precedence, arithmetic and string concat", async () => {
    expect(await evalWith("return 1 + 2 * 3")).toBe(7);
    expect(await evalWith('return "a" + "b"')).toBe("ab");
    expect(await evalWith('return "count: " + 3')).toBe("count: 3");
    expect(await evalWith("return 10 - 3 - 2")).toBe(5);
    expect(await evalWith("return 2 * 3 + 1")).toBe(7);
    expect(await evalWith("return 5 % 2")).toBe(1);
    expect(await evalWith('return "abc" < "abd"')).toBe(true);
    expect(await evalWith("return !(1 < 2)")).toBe(false);
  });

  test("ternaries and locals", async () => {
    expect(await evalWith("return true ? 1 : 2")).toBe(1);
    expect(await evalWith("let x = 2; x += 3; return x")).toBe(5);
    expect(await evalWith('let x = 1; if (x === 1) { return "one" } else { return "other" }')).toBe("one");
    expect(await evalWith('let x = 9; if (x === 1) { return "one" } return "other"')).toBe("other");
  });

  test("while loops with an explicit index", async () => {
    expect(await evalWith(`
      let total = 0;
      let i = 0;
      while (i < 4) { total = total + i; i = i + 1; }
      return total
    `)).toBe(6);
    expect(await evalWith(`
      let names = ["ana", "bob"];
      let out = "";
      let i = 0;
      while (i < names.length) { out = out + names[i]; i = i + 1; }
      return out
    `)).toBe("anabob");
  });

  test("object and array literals with member access", async () => {
    expect(await evalWith(`
      const user = { email: "a@b.test", nested: { deep: 5 } };
      return user.nested.deep * 2
    `)).toBe(10);
    expect(await evalWith('return ["b", "c"][1]')).toBe("c");
  });

  test("equality forms and logical short-circuit", async () => {
    expect(await evalWith('return 1 == "1"')).toBe(true);
    expect(await evalWith('return 1 === "1"')).toBe(false);
    expect(await evalWith('let side = 0; let f = false; f && (side = 1); return side')).toBe(0);
    expect(await evalWith('let side = 0; let t = true; t || (side = 1); return side')).toBe(0);
  });

  test("unknown identifiers and blocked constructs throw", async () => {
    await expect(evalWith("return missing_var")).rejects.toThrow("unknown identifier");
    await expect(evalWith("new Date()")).rejects.toThrow("unsupported construct");
    await expect(evalWith("import x")).rejects.toThrow("unsupported construct");
    await expect(evalWith("return globalThis")).rejects.toThrow("unknown identifier");
  });

  test("prototype tricks are unreachable", async () => {
    const data = { user: { roles: ["admin"] } };
    await expect(evalWith('return data.user.constructor === Object', { data })).rejects.toThrow("not permitted");
    await expect(evalWith('return data["__proto__"]', { data })).rejects.toThrow("not permitted");
    expect(await evalWith('return data.user.roles.indexOf("admin") >= 0', { data })).toBe(true);
  });

  test("method allowlist bounds string and array helpers", async () => {
    expect(await evalWith('return "Hello".toLowerCase()')).toBe("hello");
    expect(await evalWith('return "a,b,c".split(",")[1]')).toBe("b");
    expect(await evalWith('return ["b"].concat(["c"])[1]')).toBe("c");
    expect(await evalWith('return "abc".charCodeAt(0)')).toBe(97);
    await expect(evalWith('return [].map(1)')).rejects.toThrow("use a while loop");
    await expect(evalWith('let o = {a: 1}; return o.toString()')).rejects.toThrow("not allowed");
  });

  test("return inside loops escapes the whole program", async () => {
    expect(await evalWith(`
      let i = 0;
      while (true) {
        i = i + 1;
        if (i === 5) { return i }
        if (i > 4) { return -1 }
      }
    `, {}, 10_000)).toBe(5);
  });

  test("the step budget terminates pathological loops", async () => {
    await expect(evalWith("while (true) {}", {}, 1_000)).rejects.toThrow("budget");
  });

  test("assignment into context objects writes through", async () => {
    const callerContext: Record<string, unknown> = { prompt_data: { email: "x@y.test", username: "old" } };
    const result = await evaluateExpression(
      'context["prompt_data"]["username"] = context["prompt_data"]["email"]; return true',
      () => ({ context: callerContext }),
    );
    expect(result.value).toBe(true);
    expect((callerContext.prompt_data as Record<string, unknown>).username).toBe("x@y.test");
  });
});

describe("expression helpers", () => {
  test("regex_match and regex_replace", async () => {
    // request.user is null in this environment; reading its members throws.
    await expect(evalHelpers('return regex_match(request.user.username, ".*admin.*")')).rejects.toThrow("cannot read properties of null");
    expect((await evalHelpers('return regex_match("not-admin-jane", ".*admin.*")')).value).toBe(true);
    expect((await evalHelpers('return regex_match("jane", ".*admin.*")')).value).toBe(false);
    expect((await evalHelpers('return regex_replace("jane@corp.test", "(.+)@.+", "")')).value).toBe("");
  });

  test("list_flatten returns the first element, null or the value", async () => {
    expect((await evalHelpers('return list_flatten(["foo"])')).value).toBe("foo");
    expect((await evalHelpers("return list_flatten([])")).value).toBeNull();
    expect((await evalHelpers('return list_flatten("x")')).value).toBe("x");
  });

  test("ip_in_subnet implements v4 subnet membership", async () => {
    expect((await evalHelpers('return ip_in_subnet("192.0.2.55", "192.0.2.0/24")')).value).toBe(true);
    expect((await evalHelpers('return ip_in_subnet("192.0.3.1", "192.0.2.0/24")')).value).toBe(false);
    expect((await evalHelpers('return ip_in_subnet("10.1.2.3", "10.0.0.0/8")')).value).toBe(true);
    await expect(evalHelpers('return ip_in_subnet("bad", "10.0.0.0/8")')).rejects.toThrow("invalid IPv4");
  });

  test("request/context/ak_client_ip are exposed and writable", async () => {
    const ctx: Record<string, unknown> = { pending_user: "jane" };
    expect((await evalHelpers(
      'request.context["redirect_stage_target"] = "ak-flow://next"; return ak_client_ip === "10.0.0.7" && context.pending_user === "jane"',
      ctx,
      "10.0.0.7",
    )).value).toBe(true);
    expect(ctx.redirect_stage_target).toBe("ak-flow://next");
  });
});
