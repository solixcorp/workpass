/**
 * The application access-policy engine: per-application group gating,
 * authentication-method constraints, token lifetimes, prior-success bypass
 * windows and enforcement modes. Policy subjects are protocol-qualified:
 * "saml:<entityId>", "oidc:<clientId>", "wsfed:<realm>", "swa:<origin>".
 *
 * Evaluation contract:
 * - groups: an empty configured group set is open to every authenticated
 *   user; a non-empty set requires intersection with the user's memberships.
 * - enforcement "enforce" rejects on failure; "observe" records the outcome
 *   in the audit stream but lets the request through (transition mode).
 */

import type { Env } from "../env";

export interface AppAccessPolicy {
  subject: string;
  /** csv from { password, passkey }; the login handoff offers only these. */
  allowedMethods: string;
  /** Token/assertion lifetime override in seconds; null keeps the protocol default. */
  sessionTtlSeconds: number | null;
  /** A prior successful issuance within this window skips consent friction. */
  bypassWindowSeconds: number;
  enforcementMode: "enforce" | "observe";
  /** Applications with this flag require the user to have a second factor. */
  requireMfa: boolean;
  groups: string[];
}

export interface PolicyEvaluation {
  allowed: boolean;
  /** Set when enforcement mode is observe and a rule failed. */
  observedOnly: boolean;
  reason: string | null;
}

const SUBJECT_PATTERN = /^(saml|oidc|wsfed|swa):[A-Za-z0-9_.:\/-]{1,2000}$/;
const METHOD_PATTERN = /^[a-z]+$/;
const MAX_METHODS = 8;
const MAX_TTL_SECONDS = 43_200; // 12h
const MIN_TTL_SECONDS = 60;

export function validateAppAccessPolicy(policy: AppAccessPolicy): void {
  if (!SUBJECT_PATTERN.test(policy.subject)) throw new Error("Invalid policy subject");
  const methods = policy.allowedMethods.split(",");
  if (methods.length > MAX_METHODS || methods.some((m) => !METHOD_PATTERN.test(m))) {
    throw new Error("Invalid allowed methods");
  }
  if (
    policy.sessionTtlSeconds !== null &&
    (!Number.isInteger(policy.sessionTtlSeconds) ||
      policy.sessionTtlSeconds < MIN_TTL_SECONDS ||
      policy.sessionTtlSeconds > MAX_TTL_SECONDS)
  ) {
    throw new Error("Session TTL must be between 60s and 12h");
  }
  if (!Number.isInteger(policy.bypassWindowSeconds) || policy.bypassWindowSeconds < 0 || policy.bypassWindowSeconds > 86_400) {
    throw new Error("Bypass window must be between 0 and 24h");
  }
}

export async function upsertAppAccessPolicy(env: Env, policy: AppAccessPolicy, updatedBy: string): Promise<void> {
  validateAppAccessPolicy(policy);
  await env.DB.prepare(
    `INSERT INTO app_access_policies
       (subject, allowed_methods, session_ttl_seconds, bypass_window_seconds, enforcement_mode, require_mfa, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (subject) DO UPDATE SET
       allowed_methods = excluded.allowed_methods,
       session_ttl_seconds = excluded.session_ttl_seconds,
       bypass_window_seconds = excluded.bypass_window_seconds,
       enforcement_mode = excluded.enforcement_mode,
       require_mfa = excluded.require_mfa,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`,
  )
    .bind(
      policy.subject,
      policy.allowedMethods,
      policy.sessionTtlSeconds,
      policy.bypassWindowSeconds,
      policy.enforcementMode,
      policy.requireMfa ? 1 : 0,
      updatedBy,
      new Date().toISOString(),
    )
    .run();
  // The configured group set is the gate itself: rewrite it wholesale so an
  // update replaces the previous membership and a dropped group un-gates.
  await env.DB.prepare("DELETE FROM app_policy_groups WHERE subject = ?")
    .bind(policy.subject)
    .run();
  if (policy.groups.length > 0) {
    const statements = [];
    for (const groupId of policy.groups) {
      statements.push(
        env.DB.prepare("INSERT INTO app_policy_groups (subject, group_id) VALUES (?, ?)")
          .bind(policy.subject, groupId),
      );
    }
    await env.DB.batch(statements);
  }
}

export async function loadAppAccessPolicy(env: Env, subject: string): Promise<AppAccessPolicy | null> {
  const row = await env.DB.prepare(
    `SELECT subject, allowed_methods AS allowedMethods, session_ttl_seconds AS sessionTtlSeconds,
            bypass_window_seconds AS bypassWindowSeconds, enforcement_mode AS enforcementMode, require_mfa AS requireMfa
     FROM app_access_policies WHERE subject = ?`,
  ).bind(subject).first<{
    subject: string;
    allowedMethods: string;
    sessionTtlSeconds: number | null;
    bypassWindowSeconds: number;
    enforcementMode: "enforce" | "observe";
    requireMfa: number;
  }>();
  if (!row) return null;
  const groups = await env.DB.prepare(
    "SELECT group_id FROM app_policy_groups WHERE subject = ?",
  ).bind(subject).all<{ group_id: string }>();
  return {
    subject: row.subject,
    allowedMethods: row.allowedMethods,
    sessionTtlSeconds: row.sessionTtlSeconds,
    bypassWindowSeconds: row.bypassWindowSeconds,
    enforcementMode: row.enforcementMode as "enforce" | "observe",
    requireMfa: row.requireMfa === 1,
    groups: groups.results.map((r) => r.group_id),
  };
}

/** The group gate: an empty configured group set is open; otherwise intersection required. */
export async function userFulfillsGroupGate(env: Env, policy: AppAccessPolicy, userId: string): Promise<boolean> {
  if (policy.groups.length === 0) return true;
  if (!userId) return false;
  const memberships = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM directory_group_members
     WHERE user_id = ? AND group_id IN (${policy.groups.map(() => "?").join(", ")})`,
  )
    .bind(userId, ...policy.groups)
    .first<{ count: number }>();
  return (memberships?.count ?? 0) > 0;
}

/** Evaluate a policy for a user; returns whether the access may proceed. */
export async function evaluateAppAccess(env: Env, policy: AppAccessPolicy, userId: string): Promise<PolicyEvaluation> {
  const allowed = await userFulfillsGroupGate(env, policy, userId);
  if (allowed) return { allowed: true, observedOnly: false, reason: null };
  if (policy.enforcementMode === "observe") {
    return { allowed: true, observedOnly: true, reason: "group gate would reject (observe mode)" };
  }
  return { allowed: false, observedOnly: false, reason: "the user does not belong to a required group" };
}

/** Record a successful issuance for the prior-success bypass and the activity views. */
export async function recordAppIssuance(env: Env, subject: string, userId: string, method: string, enforcementMode: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO app_issuance_history (subject, user_id, issued_at, enforcement_mode, method)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (subject, user_id, issued_at) DO NOTHING`,
  )
    .bind(subject, userId, new Date().toISOString(), enforcementMode, method)
    .run();
}

/** A prior successful issuance within the bypass window. */
export async function hasRecentAppIssuance(env: Env, subject: string, userId: string, windowSeconds: number): Promise<boolean> {
  if (windowSeconds <= 0) return false;
  const cutoff = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const row = await env.DB.prepare(
    `SELECT issued_at FROM app_issuance_history
     WHERE subject = ? AND user_id = ? AND issued_at >= ? LIMIT 1`,
  ).bind(subject, userId, cutoff).first<{ issued_at: string }>();
  return row !== null;
}

/** The policy's token lifetime, clamped to the protocol's safety bounds. */
export function policyTtlSeconds(policy: AppAccessPolicy | null, fallbackSeconds: number): number {
  const raw = policy?.sessionTtlSeconds ?? null;
  if (raw === null || !Number.isInteger(raw)) return fallbackSeconds;
  return Math.min(Math.max(raw, MIN_TTL_SECONDS), MAX_TTL_SECONDS);
}
