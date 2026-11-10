/**
 * Access-request lifecycle tests (docs/design/access-requests.md): rule and
 * binding validation, requester eligibility and discovery, request creation
 * guards (justification, one pending per user+subject), self-review rejection,
 * the reviewer minimum-approver count, deny behavior, temporal grants honored
 * and then expired or revoked inside the policy engine, and the audit rows.
 *
 * These run against a real in-memory SQLite through the same SQL surface the
 * worker uses: `bun test tests/access-requests.test.ts`.
 */

import { describe, expect, test } from "bun:test";
import { createTestD1 } from "../test-d1";
import { ensureApplicationTables } from "../../src/db/schema";
import {
  cleanupAccessRequests,
  createAccessRequest,
  createRequestBinding,
  createRequestRule,
  hasActiveTemporalGrant,
  listRequestableForUser,
  cancelAccessRequest,
  reviewAccessRequest,
  revokeAccessRequest,
} from "../../src/access/requests";
import { evaluateAppAccess, loadAppAccessPolicy } from "../../src/access/policies";

type EnvStub = { DB: unknown };

function seededDb(env?: unknown): Promise<EnvStub> {
  const db = env ?? createTestD1().db;
  return ensureApplicationTables({ DB: db } as never).then(() => {
  const stamp = "2026-01-01T00:00:00Z";
  db.prepare("INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at) VALUES ('g-review', 'reviewers', '', 'a', ?, ?)").bind(stamp, stamp).run();
  db.prepare("INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at) VALUES ('g-app', 'app-users', '', 'a', ?, ?)").bind(stamp, stamp).run();
  db.prepare("INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES ('g-review', 'reviewer-1', 'a', ?)").bind(stamp).run();
  db.prepare("INSERT INTO directory_group_members (group_id, user_id, granted_by, granted_at) VALUES ('g-review', 'reviewer-2', 'a', ?)").bind(stamp).run();
  db.prepare("INSERT INTO swa_applications (id, name, origin, enabled, created_by, created_at) VALUES ('swa-1', 'Widget', 'https://app.test', 1, 'a', ?)").bind(stamp).run();
  return { DB: db };
  });
}

function gatePolicy(subject: string) {
  return {
    subject,
    allowedMethods: "password,passkey",
    sessionTtlSeconds: null,
    bypassWindowSeconds: 3600,
    enforcementMode: "enforce" as const,
    requireMfa: false,
    groups: ["g-app"],
  };
}

const SUBJECT = "swa:https://app.test";
const OPEN_SUBJECT = "oidc:client-alpha";

describe("rules and bindings validation", () => {
  test("rejects invalid rule names, reviewer counts and expiry bounds", async () => {
    const env = await seededDb();
    await expect(createRequestRule(env as never, { name: "bad name!" }, "admin")).rejects.toThrow("Invalid rule name");
    await expect(createRequestRule(env as never, { name: "jit", minReviewers: 6 }, "admin")).rejects.toThrow("minReviewers");
    await expect(createRequestRule(env as never, { name: "jit", notifyMode: "sometimes" }, "admin")).rejects.toThrow("notifyMode");
    await expect(createRequestBinding(env as never, { subject: SUBJECT, ruleId: "missing" }, "admin")).rejects.toThrow("Unknown request rule");
    const rule = await createRequestRule(env as never, { name: "jit", minReviewers: 1, reviewerUsers: ["reviewer-1"] }, "admin");
    await expect(
      createRequestBinding(env as never, { subject: SUBJECT, ruleId: rule.id, maxGrantedExpirySeconds: 60 }, "admin"),
    ).rejects.toThrow("maxGrantedExpirySeconds");
    await expect(
      createRequestBinding(env as never, { subject: "not-a-subject", ruleId: rule.id }, "admin"),
    ).rejects.toThrow("subject must be");
    // One binding per subject.
    await createRequestBinding(env as never, { subject: SUBJECT, ruleId: rule.id }, "admin");
    await expect(createRequestBinding(env as never, { subject: SUBJECT, ruleId: rule.id }, "admin")).rejects.toThrow("already has a request rule binding");
  });
});

describe("requester eligibility and discovery", () => {
  async function setup(subject: string, requesterUsers: string[]) {
    const env = await seededDb();
    const rule = await createRequestRule(env as never, { name: "jit", minReviewers: 1, reviewerUsers: ["reviewer-1"] }, "admin");
    const binding = await createRequestBinding(
      env as never,
      { subject, ruleId: rule.id, pendingExpirySeconds: 3600, maxGrantedExpirySeconds: 86_400, requesterUsers },
      "admin",
    );
    return { env, rule, binding };
  }

  test("a restricted binding is requestable only by bound users", async () => {
    const { env } = await setup(SUBJECT, ["requester-1"]);
    const requestable = await listRequestableForUser(env as never, "requester-1");
    expect(requestable.map((r) => r.subject)).toContain(SUBJECT);
    expect(requestable.find((r) => r.subject === SUBJECT)?.displayName).toBe("Widget");
    expect((await listRequestableForUser(env as never, "stranger")).find((r) => r.subject === SUBJECT)).toBeUndefined();
  });

  test("registry apps (app:<slug>) show their registry name", async () => {
    const { env } = await setup("app:wiki", ["requester-1"]);
    const stamp = "2026-01-01T00:00:00Z";
    (env.DB as { prepare: (sql: string) => { bind: (...args: unknown[]) => { run: () => unknown } } })
      .prepare(
        "INSERT INTO applications (id, slug, name, description, protocol, enabled, created_by, created_at, updated_at) VALUES ('app-1', 'wiki', '사내 위키', '', 'bookmark', 1, 'a', ?, ?)",
      ).bind(stamp, stamp).run();
    const requestable = await listRequestableForUser(env as never, "requester-1");
    expect(requestable.find((r) => r.subject === "app:wiki")?.displayName).toBe("사내 위키");
  });

  test("an empty requester set is open to every user", async () => {
    const { env } = await setup(OPEN_SUBJECT, []);
    expect((await listRequestableForUser(env as never, "anyone")).some((r) => r.subject === OPEN_SUBJECT)).toBe(true);
  });
});

describe("request lifecycle", () => {
  async function scenario(opts: { minReviewers?: number; requesterUsers?: string[] } = {}) {
    const env = await seededDb();
    const rule = await createRequestRule(
      env as never,
      {
        name: "jit",
        minReviewers: opts.minReviewers ?? 1,
        notifyMode: "all",
        reviewerUsers: ["reviewer-1", "reviewer-2"],
      },
      "admin",
    );
    const binding = await createRequestBinding(
      env as never,
      {
        subject: SUBJECT,
        ruleId: rule.id,
        pendingExpirySeconds: 3600,
        maxGrantedExpirySeconds: 86_400,
        requesterUsers: opts.requesterUsers ?? [],
      },
      "admin",
    );
    return { env, rule, binding };
  }

  test("creates a pending request with guards, and the reviewer queue matches eligibility", async () => {
    const { env } = await scenario();
    await expect(
      createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-1", justification: "   " }),
    ).rejects.toThrow("justification");
    const created = await createAccessRequest(env as never, {
      subject: SUBJECT,
      userId: "requester-1",
      justification: "Deploy window",
      requestedExpirySeconds: 7200,
    });
    expect(created.status).toBe("pending");
    // One pending request per user+subject.
    await expect(
      createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-1", justification: "again" }),
    ).rejects.toThrow("pending request already exists");
    // The requester never sees their own request in their review queue.
    expect((await reviewQueueFor(env, "requester-1")).find((r) => r.id === created.id)).toBeUndefined();
    expect((await reviewQueueFor(env, "reviewer-1")).some((r) => r.id === created.id)).toBe(true);
    expect((await reviewQueueFor(env, "no-such-reviewer")).some((r) => r.id === created.id)).toBe(false);
    // The requester can cancel their own pending request.
    expect(await cancelAccessRequest(env as never, "nosuch", "requester-1")).toBeNull();
    expect(await cancelAccessRequest(env as never, created.id, "requester-1")).toBe("cancelled");
    // But not twice.
    expect(await cancelAccessRequest(env as never, created.id, "requester-1")).toBeNull();
  });

  test("reviewer rules refuse self-review, non-reviewers, and denial beats approval", async () => {
    const { env } = await scenario();
    const created = await createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-1", justification: "Deploy window" });
    await expect(
      reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "requester-1", decision: "approved" }),
    ).rejects.toThrow("cannot review their own request");
    await expect(
      reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "interloper", decision: "denied" }),
    ).rejects.toThrow("not a reviewer");
    const denied = await reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "reviewer-1", decision: "denied", note: "not yet" });
    expect(denied?.newStatus).toBe("denied");
    // Decided requests are closed: further reviews land with no status change.
    expect(await reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "reviewer-2", decision: "approved" })).toBeNull();
    // The deny is on the record with the note.
    const row = await env.DB.prepare("SELECT status, decided_by AS decidedBy, decision_note AS note FROM access_requests WHERE id = ?")
      .bind(created.id).first<{ status: string; decidedBy: string; note: string }>();
    expect(row?.status).toBe("denied");
    expect(row?.decidedBy).toBe("reviewer-1");
    expect(row?.note).toBe("not yet");
  });

  test("minimum-approver counting with an active grant honored by the policy engine", async () => {
    const { env } = await scenario({ minReviewers: 2 });
    const created = await createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-1", justification: "Deploy window" });
    // Gate check before the grant: denied by the group gate.
    const policy = gatePolicy(SUBJECT);
    expect((await evaluateAppAccess(env as never, policy, "requester-1")).allowed).toBe(false);
    // First approval: below the minimum; no grant yet.
    const first = await reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "reviewer-1", decision: "approved" });
    expect(first?.newStatus).toBeNull();
    expect((await evaluateAppAccess(env as never, policy, "requester-1")).allowed).toBe(false);
    // Second approval reaches the minimum and writes the temporal grant.
    const second = await reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "reviewer-2", decision: "approved" });
    expect(second?.newStatus).toBe("approved");
    expect(await hasActiveTemporalGrant(env as never, SUBJECT, "requester-1")).toBe(true);
    // The grant satisfies the group gate in the policy engine.
    expect((await evaluateAppAccess(env as never, policy, "requester-1")).allowed).toBe(true);
    // Users without a grant remain gated.
    expect((await evaluateAppAccess(env as never, policy, "someone-else")).allowed).toBe(false);
  });

  test("expiry and revocation deactivate the grant without standing-policy edits", async () => {
    const { env } = await scenario();
    const created = await createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-1", justification: "Deploy window" });
    const approved = await reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "reviewer-1", decision: "approved" });
    expect(approved?.newStatus).toBe("approved");
    const policy = gatePolicy(SUBJECT);
    expect((await evaluateAppAccess(env as never, policy, "requester-1")).allowed).toBe(true);
    // No standing policy was modified: no policy row was ever written.
    expect(await loadAppAccessPolicy(env as never, SUBJECT)).toBeNull();
    // Expiry is read-time: shifting the grant into the past disables it.
    await env.DB.prepare("UPDATE app_temporal_grants SET expires_at = '2000-01-01T00:00:00Z' WHERE request_id = ?").bind(created.id).run();
    expect(await hasActiveTemporalGrant(env as never, SUBJECT, "requester-1")).toBe(false);
    expect((await evaluateAppAccess(env as never, policy, "requester-1")).allowed).toBe(false);
    // A fresh request can be revoked before expiry by an administrator.
    const created2 = await createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-2", justification: "Cover shift" });
    await reviewAccessRequest(env as never, { requestId: created2.id, reviewerId: "reviewer-1", decision: "approved" });
    expect(await revokeAccessRequest(env as never, created2.id, "admin")).toBe(true);
    expect(await hasActiveTemporalGrant(env as never, SUBJECT, "requester-2")).toBe(false);
    // Revoking again finds no active grant.
    expect(await revokeAccessRequest(env as never, created2.id, "admin")).toBe(false);
  });

  test("scheduled cleanup lapses expired pending requests", async () => {
    const { env } = await scenario();
    const created = await createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-1", justification: "Deploy window" });
    // Pending expiry is one hour ahead; run cleanup far in the future.
    await cleanupAccessRequests(env as never, Date.now() + 86_400_000);
    const row = await env.DB.prepare("SELECT status FROM access_requests WHERE id = ?").bind(created.id).first<{ status: string }>();
    expect(row?.status).toBe("lapsed");
  });

  test("audit rows record the request lifecycle events", async () => {
    const { env } = await scenario();
    const created = await createAccessRequest(env as never, { subject: SUBJECT, userId: "requester-1", justification: "Deploy window" });
    await reviewAccessRequest(env as never, { requestId: created.id, reviewerId: "reviewer-1", decision: "approved" });
    const types = await env.DB.prepare("SELECT event_type, outcome FROM audit_events ORDER BY log_pos ASC").all<{ event_type: string; outcome: string }>();
    const names = types.results.map((row) => row.event_type);
    expect(names).toContain("access_request.approved");
    const denied = await env.DB.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE outcome = 'failure'").first<{ count: number }>();
    // All lifecycle transitions succeeded end to end.
    await expect(denied?.count).toBe(0);
  });
});

async function reviewQueueFor(env: EnvStub, reviewerId: string) {
  const { listReviewQueue } = await import("../../src/access/requests");
  return listReviewQueue(env as never, reviewerId);
}
