import { test } from "bun:test";
import { createTestD1 } from "./test-d1";
import { ensureApplicationTables } from "../src/db/schema";
import { insertAuditEvent } from "../src/audit/store";
import { dispatchPendingEventNotifications } from "../src/policies/notifications";
import { enforcePasswordEntry, evaluateLoginSurface } from "../src/policies/password-entry";
import { evaluateTyped } from "../src/policies/registry";
import { akqlMatch } from "../src/policies/akql";

const main = async () => {
  const created = createTestD1();
  const db = created.db;
  const env = { DB: db, AUTH_BASE_URL: "https://idp.test" } as never;
  await ensureApplicationTables(env as never);
  const ruleId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO notification_rules (id, name, transports, enabled, created_by, created_at)
     VALUES (?, 'notify-breach', ?, 1, 'admin', '2026-01-01T00:00:00Z')`,
  ).bind(ruleId, JSON.stringify([{ kind: "webhook", url: "https://hooks.example.test/events" }])).run();
  const policyId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO policies (id, name, type, config, enabled, execution_logging, created_by, created_at)
     VALUES (?, 'match-audit-failure', 'event_matcher', ?, 1, 0, 'admin', '2026-01-01T00:00:00Z')`,
  ).bind(policyId, JSON.stringify({ query: 'action = "authentication.opaque.login"' })).run();
  const row = await db.prepare("SELECT id, name, type, config FROM policies WHERE name = 'match-audit-failure'").first();
  console.log("policy-row:", JSON.stringify(row));
  const bindings = await db.prepare("SELECT id, target, target_ref FROM policy_bindings").all();
  console.log("policy-bindings before bind:", JSON.stringify(bindings.results ?? bindings));
  await db.prepare(
    `INSERT INTO policy_bindings (id, target, target_ref, policy_id, order_index, mode, negate, failure_result, enabled, created_by, created_at)
     VALUES (?, 'notification_rule', ?, ?, 0, 'all', 0, 'fail', 1, 'admin', '2026-01-01T00:00:00Z')`,
  ).bind(crypto.randomUUID(), ruleId, policyId).run();
  console.log("binding ok");

  const eventId = crypto.randomUUID();
  await insertAuditEvent(env, {
    id: eventId, actor_user_id: null, target_user_id: null,
    event_type: "authentication.opaque.login", outcome: "success",
    request_path: "/api/opaque/auth/finish", client_ip: "203.0.113.44",
    event_context: { geo: { country: "KR" } },
  });
  const queued = await db.prepare("SELECT COUNT(*) AS c FROM pending_event_notifications").first();
  console.log("queued:", JSON.stringify(queued));
  const summary = await dispatchPendingEventNotifications(env, Date.now());
  console.log("dispatch:", JSON.stringify(summary));
  await enforcePasswordEntry(env, null, "x", {});
  await evaluateLoginSurface(env, null, {});
  await akqlMatch('action = "x"', { action: "x" });
  console.log("DONE");
};
await main();
