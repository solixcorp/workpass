/**
 * The expression interpreter (docs/design/authentik-policies.md): language
 * semantics, host isolation, the step budget, and helper behavior. Runs with
 * `bun test tests/policies/expression.test.ts`.
 */

import { describe, expect, test } from "bun:test";
import { evaluateExpression } from "../../src/policies/expression";

const NULL_RUNTIME = { messages: [], callPolicyByName: async () => ({ passing: false, messages: [], rawResult: null }) };
const evalWith = async (source: string, globals: Record<string, unknown> = {}, budget = 100_000) =>
  evaluateExpression(source, () => ({ ...globals }), budget);

describe("expression language semantics", () => {
  test("booleans, arithmetic, strings and ternaries", async () => {
    expect((await evalWith("return 1 + 2 * 3")).value).toBe(7);
    expect((await evalWith('return "a" + "b"')).value).toBe("ab");
    expect((await evalWith('return "count: " + 3')).value).toBe("count: 3");
    expect((await evalWith("return true ? 1 : 2")).value).toBe(1);
    expect((await evalWith("return 5 % 2")).value).toBe(1);
    expect((await evalWith('return "abc" < "abd"')).value).toBe(true);
  });

  test("locals, if/else, while loops and object literals", async () => {
    expect((await evalWith("let x = 2; x += 3; return x")).value).toBe(5);
    expect((await evalWith(`
      let total = 0;
      let i = 0;
      while (i < 4) { total = total + i; i = i + 1; }
      return total
    `)).value).toBe(6);
    expect((await evalWith(`
      const user = { email: "a@b.test", nested: { deep: 5 } };
      return user.nested.deep * 2
    `)).value).toBe(10);
    expect((await evalWith('let names = ["ana", "bob"]; let out = ""; let i = 0; while (i < names.length) { out = out + names[i]; i = i + 1; } return out')).value).toBe("anabob");
    expect((await evalWith(' let x = 1; if (x === 1) { return "one" } else { return "other" }')).value).toBe("one");
  });

  test("logical short-circuit and equality strictness", async () => {
    expect((await evalWith("return 1 == \"1\"")).value).toBe(true);
    expect((await evalWith("return 1 === \"1\"")).value).toBe(false);
    expect((await evalWith("let called = 0; let f = false; return f && (called = 1)")).value).toBe(false);
    expect((await evalWith("let called = 0; let f = true; return f || (called = 1)")).value).toBe(true);
  });

  test("unknown identifiers and blocked constructs throw", async () => {
    await expect(evalWith("return missing_var")).rejects.toThrow("unknown identifier");
    await expect(evalWith("new Date()")).rejects.toThrow("unsupported construct");
    await expect(evalWith("import x")).rejects.toThrow("unsupported construct");
    await expect(evalWith("return globalThis")).rejects.toThrow("unknown identifier");
    await expect(evalWith("return {}")).resolves.toBeDefined();
  });

  test("prototype tricks are unreachable", async () => {
    const data = { user: { roles: ["admin"] } };
    await expect(evalWith('return data.user.constructor === Object', { data })).rejects.toThrow("not permitted");
    await expect(evalWith('return data["__proto__"]', { data })).rejects.toThrow("not permitted");
    await expect(evalWith('return data.user.roles.indexOf("admin") >= 0', { data })).resolves.toBe(true);
  });

  test("method allowlist bounds string and array helpers", async () => {
    expect((await evalWith('return "Hello".toLowerCase()')).value).toBe("hello");
    expect((await evalWith('return "a,b,c".split(",")[1]')).value).toBe("b");
    expect((await evalWith('return ["b"].concat(["c"])[1]')).value).toBe("c");
    expect((await evalWith('return "abc".charCodeAt(0)')).value).toBe(97);
    await expect(evalWith('return [].map(1)')).rejects.toThrow("use a while loop");
    await expect(evalWith('let o = {a: 1}; return o.toString()')).rejects.toThrow("not allowed");
  });

  test("return inside loops escapes the whole program", async () => {
    expect((await evalWith(`
      let i = 0;
      while (true) {
        i = i + 1;
        if (i === 5) { return i }
        if (i > 4) { return -1 }
      }
    `, {}, 10_000)).value).toBe(5);
  });

  test("the step budget terminates pathological loops", async () => {
    await expect(evalWith("while (true) {}", {}, 1_000)).rejects.toThrow("budget");
    await expect(evalWith(`
      let n = 0;
      let x = 1;
      while (true) { x = x * 2; n = n + 1; if (n > 100000) { return x } }
    `, {}, 5_000)).rejects.toThrow("budget");
  });

  test("assignment into context objects writes through", async () => {
    const callerContext: Record<string, unknown> = { prompt_data: { email: "x@y.test" } };
    const result = await evaluateExpression(
      'context["prompt_data"]["username"] = context["prompt_data"]["email"]; return true',
      () => ({ context: callerContext }),
    );
    expect(result.value).toBe(true);
    expect((callerContext.prompt_data as Record<string, unknown>).username).toBe("x@y.test");
  });

  test("functions are not callable on plain data and cannot be passed around", async () => {
    await expect(evalWith("let f = callme; return f()", { callme: () => 1 })).rejects.toThrow("not callable without arguments here");
  });
});

describe("expression helpers", () => {
  test("ak_message collects messages and returns a boolean", async () => {
    const messages: string[] = [];
    const result = await evaluateExpression(
      'ak_message("denied for a reason"); return false',
      () => ({ ak_message: (m: unknown) => { messages.push(String(m)); return Boolean(m); } }),
    );
    expect(result.value).toBe(false);
    expect(messages).toEqual(["denied for a reason"]);
  });

  test("regex_match and regex_replace mirror the authentik helpers", async () => {
    expect((await evalWith('return regex_match(request.user.username, ".*admin.*")', {
      request: { user: { username: "not-admin-jane" } },
    })).value).toBe(true);
    expect((await evalWith(
      'return regex_replace(request.user.email, "(.+)@.+", "")',
      { request: { user: { email: "jane@corp.test" } } },
    )).value).toBe("jane");
  });

  test("list_flatten returns the first element, null or the value", async () => {
    expect((await evalWith("return list_flatten([\"foo\"])")).value).toBe("foo");
    expect((await evalWith("return list_flatten([])")).value).toBeNull();
    expect((await evalWith("return list_flatten(\"x\")")).value).toBe("x");
  });

  test("ip_in_subnet implements v4 subnet membership", async () => {
    expect((await evalWith('return ip_in_subnet("192.0.2.55", "192.0.2.0/24")')).value).toBe(true);
    expect((await evalWith('return ip_in_subnet("192.0.3.1", "192.0.2.0/24")')).value).toBe(false);
    expect((await evalWith('return ip_in_subnet("10.1.2.3", "10.0.0.0/8")')).value).toBe(true);
    await expect(evalWith('return ip_in_subnet("x", "10.0.0.0/8")')).rejects.toThrow("invalid IPv4");
  });

  test("ak_client_ip, request.user and context are exposed", async () => {
    const result = await evaluateExpression(
      'return ak_client_ip === "10.0.0.7" && request.user.username === "jane" && context.pending_user === "jane"',
      () => ({
        request: { user: { username: "jane", email: "j@x.test" } },
        context: { pending_user: "jane" },
        ak_client_ip: "10.0.0.7",
      }),
    );
    expect(result.value).toBe(true);
  });

  test("context mutation through request.context writes through", async () => {
    const ctx: Record<string, unknown> = {};
    await evaluateExpression('request.context["redirect_stage_target"] = "ak-flow://next"; return true', () => ({
      request: { context: ctx },
      context: ctx,
    }));
    expect(ctx.redirect_stage_target).toBe("ak-flow://next");
  });
});
