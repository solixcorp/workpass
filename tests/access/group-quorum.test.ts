import { describe, expect, test } from "bun:test";
import { createTestD1 } from "../test-d1";
import { ensureApplicationTables } from "../../src/db/schema";
import type { Env } from "../../src/env";
import {
  createAccessRequest, createRequestBinding, createRequestRule, getRequest,
  hasActiveTemporalGrant, listRequestRules, resolveRuleReviewers, reviewAccessRequest,
} from "../../src/access/requests";

const SUBJECT = "oidc:group-quorum";

async function setup(minReviewers = 1, perGroup = true) {
  const { db, sqlite } = createTestD1();
  const env = { DB: db } as unknown as Env;
  await ensureApplicationTables(env);
  for (const [groupId, members] of [
    ["security", ["security-1", "security-2"]],
    ["operations", ["operations-1", "operations-2"]],
  ] as const) {
    await db.prepare("INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at) VALUES (?, ?, '', 'admin', ?, ?)")
      .bind(groupId, groupId, new Date().toISOString(), new Date().toISOString()).run();
    for (const userId of members) {
      await db.prepare("INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES (?, ?, 'admin', ?)")
        .bind(groupId, userId, new Date().toISOString()).run();
    }
  }
  const rule = await createRequestRule(env, {
    name: "group-quorum", minReviewers, minReviewersPerGroup: perGroup,
    reviewerGroups: ["security", "operations"], reviewerUsers: ["direct-reviewer"], notifyMode: "random",
  }, "admin");
  await createRequestBinding(env, { subject: SUBJECT, ruleId: rule.id }, "admin");
  const request = await createAccessRequest(env, { subject: SUBJECT, userId: "requester", justification: "Deploy production" });
  const review = (reviewerId: string, decision: "approved" | "denied" = "approved") =>
    reviewAccessRequest(env, { requestId: request.id, reviewerId, decision });
  return { env, db, sqlite, rule, request, review };
}

describe("per-group access request approval quorums", () => {
  test("one group and direct reviewers cannot substitute for the other group", async () => {
    const { env, request, review } = await setup();
    expect((await listRequestRules(env))[0]?.minReviewersPerGroup).toBe(true);
    expect((await review("security-1"))?.newStatus).toBeNull();
    expect((await review("security-2"))?.newStatus).toBeNull();
    expect((await review("direct-reviewer"))?.newStatus).toBeNull();
    expect(await hasActiveTemporalGrant(env, SUBJECT, "requester")).toBe(false);
    expect((await getRequest(env, request.id))?.status).toBe("pending");
    expect((await review("operations-1"))?.newStatus).toBe("approved");
    expect(await hasActiveTemporalGrant(env, SUBJECT, "requester")).toBe(true);
  });

  test("each group needs N distinct approvals and a duplicate vote adds nothing", async () => {
    const { env, request, review } = await setup(2);
    await review("security-1");
    await expect(review("security-1")).rejects.toThrow();
    await review("operations-1");
    expect((await review("security-2"))?.newStatus).toBeNull();
    expect(await hasActiveTemporalGrant(env, SUBJECT, "requester")).toBe(false);
    expect((await review("operations-2"))?.newStatus).toBe("approved");
    expect((await getRequest(env, request.id))?.status).toBe("approved");
  });

  test("total-quorum rules continue to accept approvals from a single group", async () => {
    const { env, review } = await setup(2, false);
    expect((await listRequestRules(env))[0]?.minReviewersPerGroup).toBe(false);
    expect((await review("security-1"))?.newStatus).toBeNull();
    expect((await review("security-2"))?.newStatus).toBe("approved");
  });

  test("a veto still denies immediately and self-review remains prohibited", async () => {
    const { env, request, review } = await setup();
    await expect(review("requester")).rejects.toThrow("cannot review their own request");
    await review("security-1");
    expect((await review("operations-1", "denied"))?.newStatus).toBe("denied");
    expect(await review("operations-2")).toBeNull();
    expect((await getRequest(env, request.id))?.status).toBe("denied");
    expect(await hasActiveTemporalGrant(env, SUBJECT, "requester")).toBe(false);
  });

  test("current membership is required for a previously recorded group approval", async () => {
    const { db, review } = await setup();
    await review("security-1");
    await db.prepare("DELETE FROM directory_group_members WHERE group_id = 'security' AND user_id = 'security-1'").run();
    expect((await review("operations-1"))?.newStatus).toBeNull();
    expect((await review("security-2"))?.newStatus).toBe("approved");
  });

  test("overlapping members count once in each group they belong to", async () => {
    const { db, review } = await setup();
    await db.prepare("INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES ('operations', 'security-1', 'admin', ?)")
      .bind(new Date().toISOString()).run();
    expect((await review("security-1"))?.newStatus).toBe("approved");
  });

  test("membership removal immediately before finalization prevents the grant", async () => {
    const { env, db, sqlite, review } = await setup();
    await review("security-1");
    const prepare = db.prepare.bind(db);
    db.prepare = (sql: string) => {
      if (sql.includes("SET status = 'approved'")) {
        sqlite.exec("DELETE FROM directory_group_members WHERE group_id = 'security'");
      }
      return prepare(sql);
    };
    expect((await review("operations-1"))?.newStatus).toBeNull();
    expect(await hasActiveTemporalGrant(env, SUBJECT, "requester")).toBe(false);
  });

  test("an empty group or loss of all group bindings never grants access", async () => {
    const { env, db, request, rule, review } = await setup();
    await db.prepare("DELETE FROM directory_group_members WHERE group_id = 'operations'").run();
    expect((await review("security-1"))?.newStatus).toBeNull();
    await db.prepare("DELETE FROM request_rule_reviewer_groups WHERE rule_id = ?").bind(rule.id).run();
    expect((await review("direct-reviewer"))?.newStatus).toBeNull();
    expect((await getRequest(env, request.id))?.status).toBe("pending");
    expect(await hasActiveTemporalGrant(env, SUBJECT, "requester")).toBe(false);
  });

  test("random notices cover each group, deduplicate and exclude the requester before sampling", async () => {
    const { env, db, rule } = await setup(2);
    await db.prepare("INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES ('security', 'requester', 'admin', ?)")
      .bind(new Date().toISOString()).run();
    const selected = await resolveRuleReviewers(env, rule.id, 2, "random", "requester");
    expect(selected.sort()).toEqual(["operations-1", "operations-2", "security-1", "security-2"]);
    const all = await resolveRuleReviewers(env, rule.id, 2, "all", "requester");
    expect(all).toContain("direct-reviewer");
    expect(all).not.toContain("requester");
    expect(new Set(all).size).toBe(all.length);
  });

  test("group quorum configuration rejects missing groups and non-boolean flags", async () => {
    const { env } = await setup();
    for (const flag of ["false", 1, null]) {
      await expect(createRequestRule(env, { name: "bad", minReviewersPerGroup: flag, reviewerGroups: ["security"] }, "admin"))
        .rejects.toThrow("must be a boolean");
    }
    await expect(createRequestRule(env, { name: "empty", minReviewersPerGroup: true, reviewerGroups: [] }, "admin"))
      .rejects.toThrow("at least one reviewer group");
    await expect(createRequestRule(env, { name: "invalid-group", minReviewersPerGroup: true, reviewerGroups: ["security", null] }, "admin"))
      .rejects.toThrow("valid reviewer group IDs");
    const legacy = await createRequestRule(env, { name: "default", reviewerUsers: ["direct-reviewer"] }, "admin");
    expect(legacy.minReviewersPerGroup).toBe(false);
  });

  test("migration preserves existing rules and is safe to run again", async () => {
    const { db } = createTestD1();
    await db.prepare(`CREATE TABLE request_rules (
      id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL UNIQUE, min_reviewers INTEGER NOT NULL DEFAULT 1,
      notify_mode TEXT NOT NULL DEFAULT 'all', created_by TEXT NOT NULL, created_at TEXT NOT NULL
    )`).run();
    await db.prepare("INSERT INTO request_rules VALUES ('old', 'legacy-rule', 2, 'all', 'admin', ?)")
      .bind(new Date().toISOString()).run();
    const env = { DB: db } as unknown as Env;
    await ensureApplicationTables(env);
    await ensureApplicationTables(env);
    expect((await listRequestRules(env))[0]).toMatchObject({ id: "old", minReviewers: 2, minReviewersPerGroup: false });
  });
});
