/**
 * Per-application claim release policy. The global operator flags
 * (ENABLE_ACCOUNT_CLAIMS / ENABLE_ATTRIBUTE_CLAIMS) decide whether released
 * claims are possible at all; a policy row for one subject narrows which
 * kinds that application actually receives, evaluated as an AND with the
 * flags. Subjects share the app-access-policy namespace:
 * "saml:<entityId>", "oidc:<clientId>", "wsfed:<realm>". No row means the
 * flags alone decide (flag-only default).
 *
 * The optional attribute allowlist narrows the released user-attribute keys
 * further: when set, only listed keys flow to the subject.
 */

import type { Env } from "../env";
import type { AttributeValue } from "../objects/attributes";

export interface ClaimReleasePolicy {
  subject: string;
  allowAccountClaims: boolean;
  allowUserAttributes: boolean;
  /** null = the full attribute set the flags permit. */
  attributeAllowlist: string[] | null;
}

const SUBJECT_PATTERN = /^(saml|oidc|wsfed):[A-Za-z0-9_.:\/-]{1,2000}$/;
const ATTRIBUTE_KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const MAX_ALLOWLIST_KEYS = 32;

export type ClaimKind = "account" | "attributes";

export type AttributeAllowlistInput = string[] | null | undefined;

export function validateClaimReleasePolicy(policy: ClaimReleasePolicy): void {
  if (!SUBJECT_PATTERN.test(policy.subject)) {
    throw new Error("Invalid policy subject");
  }
}

/** Validate an allowlist input; undefined/null means "release everything". */
function parseAllowlist(value: AttributeAllowlistInput): string[] | null {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value)) throw new Error("attributeAllowlist must be an array of keys");
  if (value.length > MAX_ALLOWLIST_KEYS) {
    throw new Error(`attributeAllowlist must contain at most ${MAX_ALLOWLIST_KEYS} keys`);
  }
  if (value.some((key) => typeof key !== "string" || !ATTRIBUTE_KEY_PATTERN.test(key))) {
    throw new Error("attributeAllowlist keys must be 1-64 characters from [A-Za-z0-9_.:-]");
  }
  return Array.from(new Set(value as string[]));
}

export async function upsertClaimReleasePolicy(
  env: Env,
  input: {
    subject: string;
    allowAccountClaims: boolean;
    allowUserAttributes: boolean;
    attributeAllowlist?: AttributeAllowlistInput;
  },
  updatedBy: string,
): Promise<void> {
  if (!SUBJECT_PATTERN.test(input.subject)) {
    throw new Error("Invalid policy subject");
  }
  const allowlist = parseAllowlist(input.attributeAllowlist);
  await env.DB.prepare(
    `INSERT INTO claim_release_policies
       (subject, allow_account_claims, allow_user_attributes, attribute_allowlist, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (subject) DO UPDATE SET
       allow_account_claims = excluded.allow_account_claims,
       allow_user_attributes = excluded.allow_user_attributes,
       attribute_allowlist = excluded.attribute_allowlist,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`,
  )
    .bind(input.subject, input.allowAccountClaims ? 1 : 0, input.allowUserAttributes ? 1 : 0,
      allowlist === null ? null : JSON.stringify(allowlist), updatedBy, new Date().toISOString())
    .run();
}

function rowToPolicy(row: { subject: string; allowAccountClaims: number; allowUserAttributes: number; attributeAllowlist: string | null }): ClaimReleasePolicy {
  let attributeAllowlist: string[] | null = null;
  if (row.attributeAllowlist) {
    try {
      const parsed = JSON.parse(row.attributeAllowlist) as unknown;
      if (Array.isArray(parsed)) {
        const keys = parseAllowlist(parsed as string[]);
        attributeAllowlist = keys;
      }
    } catch {
      // A corrupt allowlist reads as unrestricted; the write path repairs it.
    }
  }
  return {
    subject: row.subject,
    allowAccountClaims: row.allowAccountClaims === 1,
    allowUserAttributes: row.allowUserAttributes === 1,
    attributeAllowlist,
  };
}

export async function getClaimReleasePolicy(env: Env, subject: string): Promise<ClaimReleasePolicy | null> {
  const row = await env.DB.prepare(
    `SELECT subject, allow_account_claims AS allowAccountClaims, allow_user_attributes AS allowUserAttributes,
            attribute_allowlist AS attributeAllowlist
     FROM claim_release_policies WHERE subject = ?`,
  ).bind(subject).first<{ subject: string; allowAccountClaims: number; allowUserAttributes: number; attributeAllowlist: string | null }>();
  return row ? rowToPolicy(row) : null;
}

export async function listClaimReleasePolicies(env: Env): Promise<ClaimReleasePolicy[]> {
  const result = await env.DB.prepare(
    `SELECT subject, allow_account_claims AS allowAccountClaims, allow_user_attributes AS allowUserAttributes,
            attribute_allowlist AS attributeAllowlist
     FROM claim_release_policies ORDER BY subject ASC LIMIT 200`,
  ).all<{ subject: string; allowAccountClaims: number; allowUserAttributes: number; attributeAllowlist: string | null }>();
  return result.results.map(rowToPolicy);
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

/**
 * Filter a user attribute set for one subject on top of the kind decision.
 * No policy row (or a row without an allowlist) releases the full set; an
 * empty allowlist releases nothing. A policy-read failure fails closed and
 * returns an empty set.
 */
export async function userAttributesForSubject(
  env: Env,
  subject: string | null | undefined,
  attributes: Record<string, AttributeValue>,
): Promise<Record<string, AttributeValue>> {
  if (!subject) return attributes;
  let policy: ClaimReleasePolicy | null;
  try {
    policy = await getClaimReleasePolicy(env, subject);
  } catch {
    return {};
  }
  if (!policy || policy.attributeAllowlist === null) return attributes;
  const allowlist = new Set(policy.attributeAllowlist);
  return Object.fromEntries(Object.entries(attributes).filter(([key]) => allowlist.has(key)));
}
