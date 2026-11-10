import { describe, expect, test } from "bun:test";
import { createTestD1 } from "./test-d1";
import { ensureApplicationTables } from "../src/db/schema";

test("zzz minimal sequence", async () => {
  const db = createTestD1().db;
  await ensureApplicationTables({ DB: db } as never);
  const ruleId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO notification_rules (id, name, transports, enabled, created_by, created_at)
     VALUES (?, 'zzz-rule', ?, 1, 'admin', '2026-01-01T00:00:00Z')`,
  ).bind(ruleId, JSON.stringify([{ kind: "webhook", url: "https://hooks.example.test/e" }])).run();
  const ruleCheck = await db.prepare("SELECT id FROM notification_rules WHERE id = ?").bind(ruleId).first();
  const policyId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO policies (id, name, type, config, enabled, execution_logging, created_by, created_at)
     VALUES (?, 'zzz-policy', 'event_matcher', ?, 1, 0, 'admin', '2026-01-01T00:00:00Z')`,
  ).bind(policyId, JSON.stringify({ action: "authentication.opaque.login", outcome: undefined })).run();
  const row = await db.prepare("SELECT id, name, type FROM policies WHERE name = 'zzz-policy'").first();
  const allPolicies = await db.prepare("SELECT id, name FROM policies LIMIT 5").all();
  console.log("ZZZ", JSON.stringify({ ruleCheck, row, allPolicies: allPolicies.results ?? allPolicies }));
  expect(row).not.toBeNull();
  expect((allPolicies.results ?? allPolicies).length).toBeGreaterThan(0);
});
