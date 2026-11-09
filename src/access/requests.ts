/**
 * The access-request authority (docs/design/access-requests.md): just-in-time
 * application access benchmarking authentik's access requests. A user submits
 * a request against a requestable policy subject; reviewers bound to a request
 * rule approve or deny; approval grants a time-limited temporal grant that the
 * policy engine consults after the group gate fails. Grants expire by
 * comparison, so no scheduler is required for revocation; lapses of pending
 * requests are finalized by the scheduled cleanup.
 *
 * Simplifications recorded in the design doc: the request flow is a mandatory
 * justification prompt (no flow engine), the minimum-reviewer count is a total
 * (not per-group), and notifications are best-effort through a single webhook.
 */

import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";

export const REQUEST_RULE_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
export const SUBJECT_PATTERN = /^(saml|oidc|wsfed|swa):[A-Za-z0-9_.:\/-]{1,2000}$/;
const MAX_JUSTIFICATION = 2000;
const MIN_REQUESTED_EXPIRY_SECONDS = 3600;
const PENDING_EXPIRY_CAP_SECONDS = 7_776_000; // 90d
const GRANTED_EXPIRY_CAP_SECONDS = 2_592_000; // 30d
const MIN_REVIEWERS_CAP = 5;

export interface RequestRule {
  id: string;
  name: string;
  minReviewers: number;
  notifyMode: "all" | "random";
  reviewerUsers: string[];
  reviewerGroups: string[];
}

export interface RequestRuleBinding {
  id: string;
  subject: string;
  ruleId: string;
  pendingExpirySeconds: number;
  maxGrantedExpirySeconds: number;
  requesterUsers: string[];
  requesterGroups: string[];
}

export interface AccessRequestRow {
  id: string;
  subject: string;
  userId: string;
  bindingId: string;
  justification: string;
  status: "pending" | "approved" | "denied" | "cancelled" | "lapsed" | "revoked";
  requestedExpirySeconds: number;
  grantedExpiresAt: string | null;
  pendingExpiresAt: string;
  decidedAt: string | null;
  decidedBy: string | null;
  decisionNote: string | null;
  createdAt: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

/** The tamper-evident lifecycle record; engine-level by design (one outcome). */
async function auditLifecycle(
  env: Env,
  eventType: "access_request.created" | "access_request.approved" | "access_request.denied" | "access_request.cancelled" | "access_request.revoked",
  actorUserId: string,
  targetUserId: string,
): Promise<void> {
  await insertAuditEvent(env, {
    id: crypto.randomUUID(),
    actor_user_id: actorUserId,
    target_user_id: targetUserId,
    event_type: eventType,
    outcome: "success",
    request_path: "/api/access-requests",
  });
}

function isoPlus(seconds: number): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

/** An integer inside the closed interval; the fallback applies only when undefined. */
function intInRange(value: unknown, min: number, max: number, fallback: number | null = null): number | null {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value)) return null;
  if (value < min || value > max) return null;
  return value;
}

function stringList(value: unknown, maxItems: number, maxLen: number): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((v): v is string => typeof v === "string" && v.length > 0 && v.length <= maxLen))].slice(0, maxItems);
}

// ---------------------------------------------------------------------------
// Rules and bindings (administrator)
// ---------------------------------------------------------------------------

export async function createRequestRule(
  env: Env,
  input: {
    name: string;
    minReviewers?: unknown;
    notifyMode?: unknown;
    reviewerUsers?: unknown;
    reviewerGroups?: unknown;
  },
  createdBy: string,
): Promise<RequestRule> {
  if (!REQUEST_RULE_NAME_PATTERN.test(input.name)) throw new Error("Invalid rule name");
  const minReviewers = intInRange(input.minReviewers, 1, MIN_REVIEWERS_CAP, 1);
  if (minReviewers === null) throw new Error("minReviewers must be between 1 and 5");
  const notifyMode = input.notifyMode === undefined ? "all" : input.notifyMode === "random" || input.notifyMode === "all" ? input.notifyMode as "all" | "random" : null;
  if (notifyMode === null) throw new Error("notifyMode must be 'all' or 'random'");
  const reviewerUsers = stringList(input.reviewerUsers, 100, 128);
  const reviewerGroups = stringList(input.reviewerGroups, 100, 128);

  const id = crypto.randomUUID();
  const createdAt = nowIso();
  const statements = [
    env.DB.prepare("INSERT INTO request_rules (id, name, min_reviewers, notify_mode, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(id, input.name, minReviewers, notifyMode, createdBy, createdAt),
  ];
  for (const userId of reviewerUsers) {
    statements.push(env.DB.prepare("INSERT INTO request_rule_reviewers (rule_id, user_id) VALUES (?, ?)").bind(id, userId));
  }
  for (const groupId of reviewerGroups) {
    statements.push(env.DB.prepare("INSERT INTO request_rule_reviewer_groups (rule_id, group_id) VALUES (?, ?)").bind(id, groupId));
  }
  await env.DB.batch(statements);
  return { id, name: input.name, minReviewers, notifyMode, reviewerUsers, reviewerGroups };
}

export async function listRequestRules(env: Env): Promise<RequestRule[]> {
  const rows = await env.DB.prepare(
    `SELECT id, name, min_reviewers AS minReviewers, notify_mode AS notifyMode
     FROM request_rules ORDER BY name ASC LIMIT 200`,
  ).all<{ id: string; name: string; minReviewers: number; notifyMode: string }>();
  const users = await env.DB.prepare("SELECT rule_id, user_id FROM request_rule_reviewers").all<{ rule_id: string; user_id: string }>();
  const groups = await env.DB.prepare("SELECT rule_id, group_id FROM request_rule_reviewer_groups").all<{ rule_id: string; group_id: string }>();
  return rows.results.map((row) => ({
    id: row.id,
    name: row.name,
    minReviewers: row.minReviewers,
    notifyMode: row.notifyMode as "all" | "random",
    reviewerUsers: users.results.filter((u) => u.rule_id === row.id).map((u) => u.user_id),
    reviewerGroups: groups.results.filter((g) => g.rule_id === row.id).map((g) => g.group_id),
  }));
}

export async function deleteRequestRule(env: Env, id: string): Promise<number> {
  // Bindings reference the rule; refuse to orphan a gate by deleting a rule
  // that a binding still points at. Bindings must be removed first.
  const used = await env.DB.prepare("SELECT id FROM request_rule_bindings WHERE rule_id = ? LIMIT 1").bind(id).first();
  if (used) throw new Error("The rule is still bound to an application");
  const result = await env.DB.prepare("DELETE FROM request_rules WHERE id = ?").bind(id).run();
  return result.meta.changes;
}

export function validateBindingInput(input: {
  subject: string;
  pendingExpirySeconds?: unknown;
  maxGrantedExpirySeconds?: unknown;
}): void {
  if (!SUBJECT_PATTERN.test(input.subject)) {
    throw new Error('subject must be "saml:<entityId>", "oidc:<clientId>", "wsfed:<realm>" or "swa:<origin>"');
  }
  const pending = intInRange(input.pendingExpirySeconds, 60, PENDING_EXPIRY_CAP_SECONDS);
  if (pending === null) throw new Error("pendingExpirySeconds must be between 60s and 90d");
  const granted = intInRange(input.maxGrantedExpirySeconds, MIN_REQUESTED_EXPIRY_SECONDS, GRANTED_EXPIRY_CAP_SECONDS);
  if (granted === null) throw new Error("maxGrantedExpirySeconds must be between 1h and 30d");
}

export async function createRequestBinding(
  env: Env,
  input: {
    subject: string;
    ruleId: string;
    pendingExpirySeconds?: unknown;
    maxGrantedExpirySeconds?: unknown;
    requesterUsers?: unknown;
    requesterGroups?: unknown;
  },
  createdBy: string,
): Promise<RequestRuleBinding> {
  if (!SUBJECT_PATTERN.test(input.subject)) {
    throw new Error('subject must be "saml:<entityId>", "oidc:<clientId>", "wsfed:<realm>" or "swa:<origin>"');
  }
  const rule = await env.DB.prepare("SELECT id, name FROM request_rules WHERE id = ?").bind(input.ruleId).first<{ id: string }>();
  if (!rule) throw new Error("Unknown request rule");
  const existing = await env.DB.prepare("SELECT id FROM request_rule_bindings WHERE subject = ?").bind(input.subject).first();
  if (existing) throw new Error("The application already has a request rule binding");
  const pending = intInRange(input.pendingExpirySeconds, 60, PENDING_EXPIRY_CAP_SECONDS, 604_800);
  if (pending === null) throw new Error("pendingExpirySeconds must be between 60s and 90d");
  const granted = intInRange(input.maxGrantedExpirySeconds, MIN_REQUESTED_EXPIRY_SECONDS, GRANTED_EXPIRY_CAP_SECONDS, 86_400);
  if (granted === null) throw new Error("maxGrantedExpirySeconds must be between 1h and 30d");
  const requesterUsers = stringList(input.requesterUsers, 100, 128);
  const requesterGroups = stringList(input.requesterGroups, 100, 128);

  const id = crypto.randomUUID();
  const statements = [
    env.DB.prepare(
      `INSERT INTO request_rule_bindings
         (id, subject, rule_id, pending_expiry_seconds, max_granted_expiry_seconds, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, input.subject, input.ruleId, pending, granted, createdBy, nowIso()),
  ];
  for (const userId of requesterUsers) {
    statements.push(env.DB.prepare("INSERT INTO request_binding_requesters (binding_id, user_id) VALUES (?, ?)").bind(id, userId));
  }
  for (const groupId of requesterGroups) {
    statements.push(env.DB.prepare("INSERT INTO request_binding_requester_groups (binding_id, group_id) VALUES (?, ?)").bind(id, groupId));
  }
  await env.DB.batch(statements);
  return { id, subject: input.subject, ruleId: input.ruleId, pendingExpirySeconds: pending, maxGrantedExpirySeconds: granted, requesterUsers, requesterGroups };
}

export async function listRequestBindings(env: Env): Promise<RequestRuleBinding[]> {
  const rows = await env.DB.prepare(
    `SELECT id, subject, rule_id AS ruleId, pending_expiry_seconds AS pendingExpirySeconds,
            max_granted_expiry_seconds AS maxGrantedExpirySeconds
     FROM request_rule_bindings ORDER BY subject ASC LIMIT 200`,
  ).all<{ id: string; subject: string; ruleId: string; pendingExpirySeconds: number; maxGrantedExpirySeconds: number }>();
  const users = await env.DB.prepare("SELECT binding_id, user_id FROM request_binding_requesters").all<{ binding_id: string; user_id: string }>();
  const groups = await env.DB.prepare("SELECT binding_id, group_id FROM request_binding_requester_groups").all<{ binding_id: string; group_id: string }>();
  return rows.results.map((row) => ({
    ...row,
    requesterUsers: users.results.filter((u) => u.binding_id === row.id).map((u) => u.user_id),
    requesterGroups: groups.results.filter((g) => g.binding_id === row.id).map((g) => g.group_id),
  }));
}

export async function deleteRequestBinding(env: Env, id: string): Promise<number> {
  const result = await env.DB.prepare("DELETE FROM request_rule_bindings WHERE id = ?").bind(id).run();
  return result.meta.changes;
}

export async function loadRequestBindingForSubject(env: Env, subject: string): Promise<RequestRuleBinding | null> {
  const bindings = await listRequestBindingsForSubject(env, subject);
  return bindings[0] ?? null;
}

async function listRequestBindingsForSubject(env: Env, subject: string): Promise<RequestRuleBinding[]> {
  const rows = await env.DB.prepare(
    `SELECT id, subject, rule_id AS ruleId, pending_expiry_seconds AS pendingExpirySeconds,
            max_granted_expiry_seconds AS maxGrantedExpirySeconds
     FROM request_rule_bindings WHERE subject = ? LIMIT 1`,
  ).bind(subject).all<{ id: string; subject: string; ruleId: string; pendingExpirySeconds: number; maxGrantedExpirySeconds: number }>();
  const row = rows.results[0];
  if (!row) return [];
  return [{ ...row, requesterUsers: await bindingRequesterUsers(env, row.id), requesterGroups: await bindingRequesterGroups(env, row.id) }];
}

async function bindingRequesterUsers(env: Env, bindingId: string): Promise<string[]> {
  const rows = await env.DB.prepare("SELECT user_id FROM request_binding_requesters WHERE binding_id = ?").bind(bindingId)
    .all<{ user_id: string }>();
  return rows.results.map((r) => r.user_id);
}

async function bindingRequesterGroups(env: Env, bindingId: string): Promise<string[]> {
  const rows = await env.DB.prepare("SELECT group_id FROM request_binding_requester_groups WHERE binding_id = ?").bind(bindingId)
    .all<{ group_id: string }>();
  return rows.results.map((r) => r.group_id);
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------

/**
 * Requester eligibility follows the application-access convention: an empty
 * configured requester set is open to every authenticated user; otherwise the
 * user must be individually bound or a member of a bound group.
 */
export async function userEligibleToRequest(env: Env, binding: RequestRuleBinding, userId: string): Promise<boolean> {
  if (binding.requesterUsers.length === 0 && binding.requesterGroups.length === 0) return true;
  if (!userId) return false;
  if (binding.requesterUsers.includes(userId)) return true;
  const membership = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM request_binding_requester_groups rg
     JOIN directory_group_members m ON m.group_id = rg.group_id
     WHERE rg.binding_id = ? AND m.user_id = ?`,
  ).bind(binding.id, userId).first<{ count: number }>();
  return (membership?.count ?? 0) > 0;
}

/** Reviewer eligibility: individually bound, or a member of a bound group. */
export async function userEligibleToReview(env: Env, ruleId: string, userId: string): Promise<boolean> {
  const row = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM request_rule_reviewers WHERE rule_id = ? AND user_id = ?) AS direct,
       (SELECT COUNT(*) FROM request_rule_reviewer_groups rg
         JOIN directory_group_members m ON m.group_id = rg.group_id
         WHERE rg.rule_id = ? AND m.user_id = ?) AS viaGroup`,
  ).bind(ruleId, userId, ruleId, userId).first<{ direct: number; viaGroup: number }>();
  return (row?.direct ?? 0) > 0 || (row?.viaGroup ?? 0) > 0;
}

function sampledReviewers(reviewers: string[], size: number): string[] {
  if (size >= reviewers.length) return reviewers;
  const shuffled = [...reviewers];
  for (let i = shuffled.length - 1; i > 0; i -= 1) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0]! % (i + 1);
    [shuffled[i]!, shuffled[j]!] = [shuffled[j]!, shuffled[i]!];
  }
  return shuffled.slice(0, Math.max(size, 1));
}

/** All users who can review against the rule: bound users plus group members. */
export async function resolveRuleReviewers(env: Env, ruleId: string, minReviewers: number, notifyMode: string): Promise<string[]> {
  const rows = await env.DB.prepare(
    `SELECT user_id FROM request_rule_reviewers WHERE rule_id = ?
     UNION
     SELECT m.user_id FROM request_rule_reviewer_groups rg
     JOIN directory_group_members m ON m.group_id = rg.group_id
     WHERE rg.rule_id = ?`,
  ).bind(ruleId, ruleId).all<{ user_id: string }>();
  const reviewers = rows.results.map((r) => r.user_id);
  return notifyMode === "random" ? sampledReviewers(reviewers, minReviewers) : reviewers;
}

// ---------------------------------------------------------------------------
// Request lifecycle
// ---------------------------------------------------------------------------

export interface AccessRequestView extends AccessRequestRow {
  /** Friendly name resolved from the SWA application registry where available. */
  displayName: string | null;
}

async function displayNameForSubject(env: Env, subject: string): Promise<string | null> {
  const prefix = subject.slice(0, subject.indexOf(":"));
  const value = subject.slice(subject.indexOf(":") + 1);
  if (prefix === "swa") {
    const row = await env.DB.prepare("SELECT name FROM swa_applications WHERE origin = ?").bind(value)
      .first<{ name: string }>();
    return row?.name ?? null;
  }
  return null;
}

function viewFromRow(row: AccessRequestRow, displayName: string | null): AccessRequestView {
  return { ...row, displayName };
}

/** The Discover list: bindings this user is eligible to request access through. */
export async function listRequestableForUser(env: Env, userId: string): Promise<Array<{ subject: string; displayName: string | null; pendingExpirySeconds: number; maxGrantedExpirySeconds: number }>> {
  const bindings = await listRequestBindings(env);
  const out: Array<{ subject: string; displayName: string | null; pendingExpirySeconds: number; maxGrantedExpirySeconds: number }> = [];
  for (const binding of bindings) {
    if (!(await userEligibleToRequest(env, binding, userId))) continue;
    const displayName = await displayNameForSubject(env, binding.subject);
    out.push({
      subject: binding.subject,
      displayName,
      pendingExpirySeconds: binding.pendingExpirySeconds,
      maxGrantedExpirySeconds: binding.maxGrantedExpirySeconds,
    });
  }
  return out;
}

export async function createAccessRequest(
  env: Env,
  input: { subject: string; userId: string; justification: string; requestedExpirySeconds?: unknown },
  bindingOverride?: RequestRuleBinding,
): Promise<AccessRequestView> {
  if (!SUBJECT_PATTERN.test(input.subject)) throw new Error("Invalid application subject");
  const justification = input.justification.trim();
  if (justification.length === 0 || justification.length > MAX_JUSTIFICATION) {
    throw new Error("A justification of 1-2000 characters is required");
  }
  const binding = bindingOverride ?? (await loadRequestBindingForSubject(env, input.subject));
  if (!binding) throw new Error("The application is not requestable");
  if (!(await userEligibleToRequest(env, binding, input.userId))) {
    throw new Error("The user may not request access to this application");
  }
  const pendingRow = await env.DB.prepare(
    "SELECT id FROM access_requests WHERE user_id = ? AND subject = ? AND status = 'pending' LIMIT 1",
  ).bind(input.userId, input.subject).first();
  if (pendingRow) throw new Error("A pending request already exists for this application");

  const requested = intInRange(
    input.requestedExpirySeconds,
    MIN_REQUESTED_EXPIRY_SECONDS,
    binding.maxGrantedExpirySeconds,
    binding.maxGrantedExpirySeconds,
  );
  if (requested === null) {
    throw new Error(`requestedExpirySeconds must be between 1h and the binding maximum (${binding.maxGrantedExpirySeconds}s)`);
  }

  const id = crypto.randomUUID();
  const createdAt = nowIso();
  const row: AccessRequestRow = {
    id,
    subject: input.subject,
    userId: input.userId,
    bindingId: binding.id,
    justification,
    status: "pending",
    requestedExpirySeconds: requested,
    grantedExpiresAt: null,
    pendingExpiresAt: new Date(Date.now() + binding.pendingExpirySeconds * 1000).toISOString(),
    decidedAt: null,
    decidedBy: null,
    decisionNote: null,
    createdAt,
  };
  await env.DB.prepare(
    `INSERT INTO access_requests
       (id, subject, user_id, binding_id, justification, status, requested_expiry_seconds,
        granted_expires_at, pending_expires_at, decided_at, decided_by, decision_note, created_at)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, NULL, ?, NULL, NULL, NULL, ?)`,
  ).bind(id, row.subject, row.userId, row.bindingId, row.justification, row.requestedExpirySeconds, row.pendingExpiresAt, createdAt).run();
  await auditLifecycle(env, "access_request.created", row.userId, row.subject);
  return viewFromRow(row, await displayNameForSubject(env, row.subject));
}

const REQUEST_COLUMNS = `id, subject, user_id AS userId, binding_id AS bindingId, justification,
  status, requested_expiry_seconds AS requestedExpirySeconds, granted_expires_at AS grantedExpiresAt,
  pending_expires_at AS pendingExpiresAt, decided_at AS decidedAt, decided_by AS decidedBy,
  decision_note AS decisionNote, created_at AS createdAt`;

export async function getRequest(env: Env, id: string): Promise<AccessRequestView | null> {
  const row = await env.DB.prepare(`SELECT ${REQUEST_COLUMNS} FROM access_requests WHERE id = ?`).bind(id)
    .first<Omit<AccessRequestRow, never>>();
  if (!row) return null;
  return viewFromRow(row as unknown as AccessRequestRow, await displayNameForSubject(env, row.subject));
}

export async function listRequestsForUser(env: Env, userId: string): Promise<AccessRequestView[]> {
  const rows = await env.DB.prepare(
    `SELECT ${REQUEST_COLUMNS} FROM access_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`,
  ).bind(userId).all<AccessRequestRow>();
  const views: AccessRequestView[] = [];
  for (const row of rows.results) views.push(viewFromRow(row, await displayNameForSubject(env, row.subject)));
  return views;
}

/** Queue a reviewer sees: pending requests they are eligible and uninvolved in. */
export async function listReviewQueue(env: Env, reviewerId: string): Promise<AccessRequestView[]> {
  const rows = await env.DB.prepare(
    `SELECT ${REQUEST_COLUMNS} FROM access_requests
     WHERE status = 'pending' AND user_id != ? ORDER BY created_at ASC LIMIT 200`,
  ).bind(reviewerId).all<AccessRequestRow>();
  const out: AccessRequestView[] = [];
  for (const row of rows.results) {
    const view = viewFromRow(row, await displayNameForSubject(env, row.subject));
    if (await reviewEligibleAgainstRule(env, view, reviewerId)) out.push(view);
  }
  return out;
}

/** Verify the reviewer matches the rule of the request's binding. */
async function reviewEligibleAgainstRule(env: Env, request: AccessRequestRequestRuleInfo, reviewerId: string): Promise<boolean> {
  const binding = await env.DB.prepare(
    "SELECT rule_id AS ruleId FROM request_rule_bindings WHERE id = ?",
  ).bind(request.bindingId).first<{ ruleId: string }>();
  return binding !== null && (await userEligibleToReview(env, binding.ruleId, reviewerId));
}

type AccessRequestRequestRuleInfo = Pick<AccessRequestRow, "bindingId">;

export async function cancelAccessRequest(env: Env, id: string, userId: string): Promise<string | null> {
  const result = await env.DB.prepare(
    `UPDATE access_requests SET status = 'cancelled', decided_at = ?, decided_by = ?
     WHERE id = ? AND user_id = ? AND status = 'pending'`,
  ).bind(nowIso(), userId, id, userId).run();
  if (result.meta.changes !== 1) return null;
  await auditLifecycle(env, "access_request.cancelled", userId, id);
  return "cancelled";
}

export interface ReviewOutcome {
  request: AccessRequestRow;
  /** Set when the request's status changed as a result of this review. */
  newStatus: "approved" | "denied" | null;
}

/**
 * Record a review decision. A deny denies outright; approvals accumulate until
 * the rule's minimum-approver count is reached, at which point the request is
 * approved and the temporal grant is written in the same sequence. The final
 * transition is a single guarded statement, so concurrent approvals race on the
 * status guard rather than double-granting.
 */
export async function reviewAccessRequest(
  env: Env,
  input: { requestId: string; reviewerId: string; decision: "approved" | "denied"; note?: string },
): Promise<ReviewOutcome | null> {
  const request = await env.DB.prepare(`SELECT ${REQUEST_COLUMNS} FROM access_requests WHERE id = ?`)
    .bind(input.requestId).first<AccessRequestRow>();
  if (!request) return null;
  const binding = await env.DB.prepare(
    "SELECT rule_id AS ruleId FROM request_rule_bindings WHERE id = ?",
  ).bind(request.bindingId).first<{ ruleId: string }>();
  if (!binding) return null;
  const rule = await env.DB.prepare(
    "SELECT min_reviewers AS minReviewers FROM request_rules WHERE id = ?",
  ).bind(binding.ruleId).first<{ minReviewers: number }>();
  if (!rule) return null;
  if (request.userId === input.reviewerId) throw new Error("A requester cannot review their own request");
  if (!(await userEligibleToReview(env, binding.ruleId, input.reviewerId))) {
    throw new Error("The user is not a reviewer for this rule");
  }
  if (request.status !== "pending") return null;
  const note = typeof input.note === "string" ? input.note.slice(0, MAX_JUSTIFICATION) : null;

  await env.DB.prepare(
    `INSERT INTO access_request_approvals (request_id, reviewer_id, decision, note, decided_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).bind(request.id, input.reviewerId, input.decision, note, nowIso()).run();

  if (input.decision === "denied") {
    const result = await env.DB.prepare(
      `UPDATE access_requests SET status = 'denied', decided_at = ?, decided_by = ?, decision_note = ?
       WHERE id = ? AND status = 'pending'`,
    ).bind(nowIso(), input.reviewerId, note, request.id).run();
    if (result.meta.changes === 1) {
      await auditLifecycle(env, "access_request.denied", input.reviewerId, request.userId);
    }
    return {
      request: { ...request, status: result.meta.changes === 1 ? "denied" : request.status, decidedBy: input.reviewerId },
      newStatus: result.meta.changes === 1 ? "denied" : null,
    };
  }

  // Approve path: finalize only when the recorded approval count reaches the rule minimum.
  const grantedExpiresAt = new Date(
    Date.parse(request.createdAt) + request.requestedExpirySeconds * 1000,
  ).toISOString();
  const result = await env.DB.prepare(
    `UPDATE access_requests
     SET status = 'approved', granted_expires_at = ?, decided_at = ?, decided_by = ?, decision_note = ?
     WHERE id = ? AND status = 'pending'
       AND (SELECT COUNT(*) FROM access_request_approvals WHERE request_id = ? AND decision = 'approved')
           >= (SELECT min_reviewers FROM request_rules WHERE id = (SELECT rule_id FROM request_rule_bindings WHERE id = binding_id))`,
  ).bind(grantedExpiresAt, nowIso(), input.reviewerId, note, request.id, request.id).run();
  if (result.meta.changes !== 1) {
    return { request, newStatus: null };
  }
  const existingGrant = await env.DB.prepare(
    "SELECT request_id FROM app_temporal_grants WHERE request_id = ?",
  ).bind(request.id).first();
  if (!existingGrant) {
    await env.DB.prepare(
      `INSERT INTO app_temporal_grants (request_id, subject, user_id, granted_at, expires_at, approved_by)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(request.id, request.subject, request.userId, nowIso(), grantedExpiresAt, input.reviewerId).run();
    await auditLifecycle(env, "access_request.approved", input.reviewerId, request.userId);
  }
  return { request: { ...request, status: "approved", grantedExpiresAt }, newStatus: "approved" };
}

/** Administrator early revocation of an active grant. */
export async function revokeAccessRequest(env: Env, requestId: string, revokedBy: string): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE app_temporal_grants SET revoked_at = ? WHERE request_id = ? AND revoked_at IS NULL AND expires_at > ?`,
  ).bind(nowIso(), requestId, nowIso()).run();
  if (result.meta.changes !== 1) return false;
  await env.DB.prepare(
    `UPDATE access_requests SET status = 'revoked', decided_at = ?, decided_by = ?
     WHERE id = ? AND status = 'approved'`,
  ).bind(nowIso(), revokedBy, requestId).run();
  const revoked = await env.DB.prepare("SELECT user_id AS userId FROM access_requests WHERE id = ?").bind(requestId)
    .first<{ userId: string }>();
  await auditLifecycle(env, "access_request.revoked", revokedBy, revoked?.userId ?? requestId);
  return true;
}

/**
 * The policy-engine hook: an active grant (not revoked, not expired) satisfies
 * the group gate. Called only after the configured group gate has failed, so a
 * grant can never widen a policy beyond the user's own group gate.
 */
export async function hasActiveTemporalGrant(env: Env, subject: string, userId: string): Promise<boolean> {
  if (!userId || !subject) return false;
  const row = await env.DB.prepare(
    `SELECT request_id FROM app_temporal_grants
     WHERE subject = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ? LIMIT 1`,
  ).bind(subject, userId, nowIso()).first();
  return row !== null;
}

// ---------------------------------------------------------------------------
// Maintenance and notification
// ---------------------------------------------------------------------------

/** Finalize pending requests whose pending expiry passed. Scheduled cleanup. */
export async function cleanupAccessRequests(env: Env, atMs: number): Promise<void> {
  const cutoff = new Date(atMs).toISOString();
  await env.DB.prepare(
    `UPDATE access_requests SET status = 'lapsed', decided_at = ? WHERE status = 'pending' AND pending_expires_at <= ?`,
  ).bind(cutoff, cutoff).run();
}

const WEBHOOK_TIMEOUT_MS = 5_000;

/**
 * Best-effort reviewer notification. Failure is logged and swallowed: the
 * reviewer queue API remains the authoritative source of pending work.
 */
export async function notifyAccessRequestEvent(
  env: Env,
  event: {
    type: "access_request.created" | "access_request.approved" | "access_request.denied";
    requestId: string;
    subject: string;
    requesterId: string;
    justification: string;
    reviewers?: string[];
    decision?: { reviewerId: string; decision: string; note: string | null; newStatus: string | null };
  },
): Promise<void> {
  const url = env.ACCESS_REQUEST_WEBHOOK_URL;
  if (!url || url.length === 0) return;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...event, occurredAt: nowIso() }),
      signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
    });
    if (!response.ok) {
      console.warn("Access request webhook delivery failed", {
        event: event.type,
        requestId: event.requestId,
        status: response.status,
      });
    }
  } catch (error) {
    console.warn("Access request webhook delivery failed", {
      event: event.type,
      name: error instanceof Error ? error.name : "UnknownError",
    });
  }
}
