/**
 * Per-application claim release policy. The global operator flags
 * (ENABLE_ACCOUNT_CLAIMS / ENABLE_ATTRIBUTE_CLAIMS) decide whether released
 * claims are possible at all; a policy row for one subject narrows which
 * kinds that application actually receives, evaluated as an AND with the
 * flags. Subjects share the app-access-policy namespace:
 * "saml:<entityId>", "oidc:<clientId>", "wsfed:<realm>". No row means the
 * flags alone decide (flag-only default).
 */

import type { Env } from "../env";

export interface ClaimReleasePolicy {
  subject: string;
  allowAccountClaims: boolean;
  allowUserAttributes: boolean;
}

const SUBJECT_PATTERN = /^(saml|oidc|wsfed):[A-Za-z0-9_.:\/-]{1,2000}$/;

export type ClaimKind = "account" | "attributes";

export function validateClaimReleasePolicy(policy: ClaimReleasePolicy): void {
  if (!SUBJECT_PATTERN.test(policy.subject)) {
    throw new Error("Invalid policy subject");
  }
}

export async function upsertClaimReleasePolicy(env: Env, policy: ClaimReleasePolicy, updatedBy: string): Promise<void> {
  validateClaimReleasePolicy(policy);
  await env.DB.prepare(
    `INSERT INTO claim_release_policies (subject, allow_account_claims, allow_user_attributes, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (subject) DO UPDATE SET
       allow_account_claims = excluded.allow_account_claims,
       allow_user_attributes = excluded.allow_user_attributes,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`,
  )
    .bind(policy.subject, policy.allowAccountClaims ? 1 : 0, policy.allowUserAttributes ? 1 : 0, updatedBy, new Date().toISOString())
    .run();
}

export async function getClaimReleasePolicy(env: Env, subject: string): Promise<ClaimReleasePolicy | null> {
  const row = await env.DB.prepare(
    `SELECT subject, allow_account_claims AS allowAccountClaims, allow_user_attributes AS allowUserAttributes
     FROM claim_release_policies WHERE subject = ?`,
  ).bind(subject).first<{ subject: string; allowAccountClaims: number; allowUserAttributes: number }>();
  if (!row) return null;
  return { subject: row.subject, allowAccountClaims: row.allowAccountClaims === 1, allowUserAttributes: row.allowUserAttributes === 1 };
}

export async function listClaimReleasePolicies(env: Env): Promise<ClaimReleasePolicy[]> {
  const result = await env.DB.prepare(
    `SELECT subject, allow_account_claims AS allowAccountClaims, allow_user_attributes AS allowUserAttributes
     FROM claim_release_policies ORDER BY subject ASC LIMIT 200`,
  ).all<{ subject: string; allowAccountClaims: number; allowUserAttributes: number }>();
  return result.results.map((row) => ({
    subject: row.subject,
    allowAccountClaims: row.allowAccountClaims === 1,
    allowUserAttributes: row.allowUserAttributes === 1,
  }));
}

export async function deleteClaimReleasePolicy(env: Env, subject: string): Promise<boolean> {
  const removed = await env.DB.prepare("DELETE FROM claim_release_policies WHERE subject = ?").bind(subject).run();
  return removed.meta.changes === 1;
}

/**
 * Does one released claim kind flow to this subject? Global flag first
 * (fail-closed), then the per-application row; every read failure fails
 * closed.
 */
export async function claimReleaseDecision(env: Env, subject: string | null | undefined, kind: ClaimKind): Promise<boolean> {
  const flag = kind === "account" ? env.ENABLE_ACCOUNT_CLAIMS === "true" : env.ENABLE_ATTRIBUTE_CLAIMS === "true";
  if (!flag) return false;
  if (!subject) return true;
  try {
    const policy = await getClaimReleasePolicy(env, subject);
    if (!policy) return true;
    return kind === "account" ? policy.allowAccountClaims : policy.allowUserAttributes;
  } catch {
    return false;
  }
}
