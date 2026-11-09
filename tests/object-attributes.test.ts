import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../src/db/schema";
import {
  attributeObjectExists,
  deleteObjectAttributes,
  getObjectAttributes,
  isObjectAttributeType,
  parseAttributesInput,
  setObjectAttributes,
} from "../src/objects/attributes";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

async function ensureUserTable(env: Env): Promise<void> {
  // A minimal Better Auth user table: the attribute store only checks for the
  // referenced id and does not depend on other columns.
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY NOT NULL)').run();
}

function testEnv(): Env {
  return { DB: createTestD1().db } as unknown as Env;
}

describe("attribute input validation", () => {
  test("accepts a flat object of primitives", () => {
    const parsed = parseAttributesInput({ team: "backend", level: 3, oncall: true, alias: null });
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.attributes).toEqual({ team: "backend", level: 3, oncall: true, alias: null });
    }
  });

  test("rejects missing, non-object and array inputs", () => {
    for (const input of [undefined, null, "x", [], 3]) {
      const parsed = parseAttributesInput(input);
      expect(parsed.ok).toBe(false);
      if (!parsed.ok) expect(parsed.error).toContain("attributes");
    }
  });

  test("rejects invalid keys", () => {
    expect(parseAttributesInput({ "": "x" }).ok).toBe(false);
    expect(parseAttributesInput({ "a b": "x" }).ok).toBe(false);
    expect(parseAttributesInput({ [`${"k".repeat(65)}`]: "x" }).ok).toBe(false);
    expect(parseAttributesInput({ "cost-center-42": "x" }).ok).toBe(true);
  });

  test("rejects non-primitive values", () => {
    for (const value of [{ nested: 1 }, ["array"], new Date()]) {
      expect(parseAttributesInput({ key: value }).ok).toBe(false);
    }
  });

  test("rejects oversized or control-bearing strings and unsafe numbers", () => {
    expect(parseAttributesInput({ key: "x".repeat(513) }).ok).toBe(false);
    expect(parseAttributesInput({ key: "bad\u0000value" }).ok).toBe(false);
    expect(parseAttributesInput({ key: Number.NaN }).ok).toBe(false);
    expect(parseAttributesInput({ key: Number.MAX_SAFE_INTEGER + 1 }).ok).toBe(false);
  });

  test("enforces entry count and serialized size caps", () => {
    const many: Record<string, string> = {};
    for (let index = 0; index < 33; index += 1) many[`key${index}`] = "v";
    expect(parseAttributesInput(many).ok).toBe(false);
    const bulky: Record<string, string> = { big: "x".repeat(4000) };
    expect(parseAttributesInput(bulky).ok).toBe(false);
  });
});

describe("object attribute type routing", () => {
  test("recognizes the supported types only", () => {
    expect(isObjectAttributeType("user")).toBe(true);
    expect(isObjectAttributeType("group")).toBe(true);
    expect(isObjectAttributeType("account")).toBe(true);
    expect(isObjectAttributeType("session")).toBe(false);
    expect(isObjectAttributeType("User")).toBe(false);
  });
});

describe("attribute storage", () => {
  test("round-trips, replaces and clears an attribute set", async () => {
    const env = testEnv();
    await ensureApplicationTables(env);
    await ensureUserTable(env);
    await env.DB.prepare(
      `INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at)
       VALUES ('g1', 'eng', '', 'admin', '2026-01-01', '2026-01-01')`,
    ).run();
    expect(await attributeObjectExists(env, "group", "g1")).toBe(true);
    expect(await attributeObjectExists(env, "user", "g1")).toBe(false);

    await setObjectAttributes(env, "group", "g1", { team: "platform", tier: 1 }, "admin");
    const stored = await getObjectAttributes(env, "group", "g1");
    expect(stored.attributes).toEqual({ team: "platform", tier: 1 });
    expect(stored.updatedAt).not.toBeNull();

    await setObjectAttributes(env, "group", "g1", { team: "runtime" }, "admin");
    expect((await getObjectAttributes(env, "group", "g1")).attributes).toEqual({ team: "runtime" });

    expect(await deleteObjectAttributes(env, "group", "g1")).toBe(true);
    expect((await getObjectAttributes(env, "group", "g1")).attributes).toEqual({});
    // Deleting again reports that nothing was removed.
    expect(await deleteObjectAttributes(env, "group", "g1")).toBe(false);
  });

  test("an unknown object reads but does not report existence", async () => {
    const env = testEnv();
    await ensureApplicationTables(env);
    await ensureUserTable(env);
    expect(await attributeObjectExists(env, "account", "missing")).toBe(false);
    expect((await getObjectAttributes(env, "account", "missing")).attributes).toEqual({});
  });
});
