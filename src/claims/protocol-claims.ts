/**
 * Protocol claim release for multi-account switching and custom object
 * attributes. The active account of the token's session and the acting
 * user's custom attributes are added as URI-namespaced, additive claims to
 * the surfaces that can consume them:
 *
 * - OIDC access tokens and ID tokens through the oauthProvider extension
 *   claim contributors (`claims.accessToken` / `claims.idToken`, which carry
 *   the `sid`-backed session id),
 * - the JWT plugin's `definePayload` (session token, full session),
 * - SAML assertion attributes (`buildSignedSamlResponse.attributes`).
 *
 * Scope-gated claims (`phone`, `groups`) release through the same extension on
 * top of the flag-gated base, only when the client was granted the scope; see
 * `scopeClaimsForSubject`.
 *
 * Everything fails closed: without the operator flags the helpers return
 * empty claims and the surfaces are byte-identical to pre-release behavior.
 * Only the acting user's attributes are released; group attributes stay
 * unreleased pending a per-application release policy.
 */

import type { Env } from "../env";
import { getObjectAttributes, type AttributeValue } from "../objects/attributes";
import { getSessionAccountContext } from "../accounts/store";
import { claimReleaseDecision, userAttributesForSubject } from "./release-policy";

/** URI namespace for released application claims: the configured IdP origin. */
export function claimNamespace(env: Env): string {
  return `${new URL(env.AUTH_BASE_URL).origin}/claims`;
}

export const ACTIVE_ACCOUNT_CLAIM_SUFFIX = "active-account";
export const ATTRIBUTES_CLAIM_SUFFIX = "attributes";

function accountClaimsEnabled(env: Env): boolean {
  return env.ENABLE_ACCOUNT_CLAIMS === "true";
}

function attributeClaimsEnabled(env: Env): boolean {
  return env.ENABLE_ATTRIBUTE_CLAIMS === "true";
}

/**
 * Structured claim for the session's active account. Resolves through the
 * stored session id (`sid`); a session that has never switched reads as no
 * claim at all, so single-account deployments without a switch keep the
 * token claims unchanged.
 */
export async function activeAccountClaim(
  env: Env,
  sessionId: string | null,
): Promise<{ [claim: string]: unknown }> {
  return await activeAccountClaimForSubject(env, sessionId, undefined);
}

/**
 * Subject-aware variant: the requesting application's policy narrows (an AND
 * with the global flags) whether the account claim flows to it. No policy
 * row keeps flag-only behavior.
 */
export async function activeAccountClaimForSubject(
  env: Env,
  sessionId: string | null,
  subject: string | undefined,
): Promise<{ [claim: string]: unknown }> {
  if (sessionId === null || !(await claimReleaseDecision(env, subject, "account"))) return {};
  const context = await getSessionAccountContext(env, sessionId);
  if (!context) return {};
  return {
    [`${claimNamespace(env)}/${ACTIVE_ACCOUNT_CLAIM_SUFFIX}`]: {
      id: context.account.id,
      name: context.account.name,
      role: context.role,
    },
  };
}

/** The acting user's custom object attributes as one flat JSON claim. */
export async function userAttributesClaim(
  env: Env,
  userId: string | null | undefined,
): Promise<{ [claim: string]: unknown }> {
  return await userAttributesClaimForSubject(env, userId, undefined);
}

/** Subject-aware variant of the attributes claim. */
export async function userAttributesClaimForSubject(
  env: Env,
  userId: string | null | undefined,
  subject: string | undefined,
): Promise<{ [claim: string]: unknown }> {
  if (!userId || !(await claimReleaseDecision(env, subject, "attributes"))) {
    return await Promise.resolve({});
  }
  const { attributes } = await getObjectAttributes(env, "user", userId);
  const filtered = await userAttributesForSubject(env, subject, attributes);
  if (Object.keys(filtered).length === 0) return {};
  return { [`${claimNamespace(env)}/${ATTRIBUTES_CLAIM_SUFFIX}`]: filtered };
}

/** The serialized-size ceiling for any released attribute bundle. */
const GROUP_BUNDLE_LIMIT = 4096;

/**
 * The account-attributes claim for the session's active account, reusing the
 * account kind gate. The set is primitive-bounded already; no allowlist is
 * applied for this kind.
 */
export async function accountAttributesClaimForSubject(
  env: Env,
  sessionId: string | null,
  subject: string | undefined,
): Promise<{ [claim: string]: unknown }> {
  if (sessionId === null || !(await claimReleaseDecision(env, subject, "accountAttributes"))) return {};
  const context = await getSessionAccountContext(env, sessionId);
  if (!context) return {};
  const { attributes } = await getObjectAttributes(env, "account", context.account.id);
  if (Object.keys(attributes).length === 0) return {};
  return { [`${claimNamespace(env)}/account-attributes`]: attributes };
}

/**
 * Group-attribute release: the user's own directory groups only, capped to a
 * deterministic 4 KiB bundle (ascending group id order) so a member of many
 * groups cannot blow up a token.
 */
export async function groupAttributesClaimForSubject(
  env: Env,
  userId: string | null | undefined,
  subject: string | undefined,
): Promise<{ [claim: string]: unknown }> {
  if (!userId || !(await claimReleaseDecision(env, subject, "groupAttributes"))) return {};
  const rows = await env.DB.prepare(
    `SELECT g.id, o.attributes
     FROM directory_group_members m
     JOIN directory_groups g ON g.id = m.group_id
     LEFT JOIN object_attributes o ON o.object_type = 'group' AND o.object_id = g.id
     WHERE m.user_id = ?
     ORDER BY g.id ASC LIMIT 100`,
  ).bind(userId).all<{ id: string; attributes: string | null }>();
  const bundle: Record<string, unknown> = {};
  let size = 0;
  for (const row of rows.results) {
    if (!row.attributes) continue;
    let attributes: unknown;
    try { attributes = JSON.parse(row.attributes); } catch { continue; }
    if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) continue;
    const serialized = JSON.stringify({ [row.id]: attributes });
    const encoded = new TextEncoder().encode(serialized).byteLength;
    if (size + encoded > GROUP_BUNDLE_LIMIT) break;
    bundle[row.id] = attributes;
    size += encoded;
  }
  if (Object.keys(bundle).length === 0) return {};
  return { [`${claimNamespace(env)}/group-attributes`]: bundle };
}

/**
 * Scope-gated claims: released only when the granted scopes include the
 * requesting scope, on top of the fail-closed release gates.
 *
 * - "groups": the acting user's directory group names. Rides the same gate as
 *   the group-attribute bundle (ENABLE_ATTRIBUTE_CLAIMS and the per-application
 *   `allowGroupAttributes` policy), capped to the same 100-group read.
 * - "phone": the phone number recorded by the phoneNumber plugin, released with
 *   its verification status per OIDC Core §5.4.
 */
export async function scopeClaimsForSubject(
  env: Env,
  userId: string | null | undefined,
  subject: string | undefined,
  scopes: string[] | undefined,
  user: { phoneNumber?: unknown; phoneNumberVerified?: unknown } | null | undefined,
): Promise<{ [claim: string]: unknown }> {
  if (!userId || !scopes || scopes.length === 0) return {};
  const claims: { [claim: string]: unknown } = {};
  if (scopes.includes("groups") && (await claimReleaseDecision(env, subject, "groupAttributes"))) {
    const result = await env.DB.prepare(
      `SELECT g.name
       FROM directory_group_members m
       JOIN directory_groups g ON g.id = m.group_id
       WHERE m.user_id = ?
       ORDER BY g.id ASC LIMIT 100`,
    ).bind(userId).all<{ name: string }>();
    const names = result.results.map((row) => row.name);
    if (names.length > 0) claims.groups = names;
  }
  if (scopes.includes("phone") && user) {
    if (typeof user.phoneNumber === "string" && user.phoneNumber.length > 0) {
      claims.phone_number = user.phoneNumber;
      claims.phone_number_verified = user.phoneNumberVerified === true;
    }
  }
  return claims;
}

/** The merged OIDC claim set for both the access-token and ID-token paths. */
export async function oidcClaimRelease(
  env: Env,
  sessionId: string | null | undefined,
  userId: string | null | undefined,
): Promise<Record<string, unknown>> {
  return await oidcClaimReleaseForSubject(env, sessionId, userId, undefined);
}

/** Subject-aware merged release: per-application policy over the flags. */
export async function oidcClaimReleaseForSubject(
  env: Env,
  sessionId: string | null | undefined,
  userId: string | null | undefined,
  subject: string | undefined,
): Promise<Record<string, unknown>> {
  if (!accountClaimsEnabled(env) && !attributeClaimsEnabled(env)) return {};
  return {
    ...(await activeAccountClaimForSubject(env, sessionId ?? null, subject)),
    ...(await accountAttributesClaimForSubject(env, sessionId ?? null, subject)),
    ...(await userAttributesClaimForSubject(env, userId, subject)),
    ...(await groupAttributesClaimForSubject(env, userId, subject)),
  };
}

/**
 * SAML attribute release: every value is a simple string, per the SAML 2.0
 * attribute profile. Attributes are returned sorted by name so the canonical
 * assertion construction stays deterministic. Null custom attributes are
 * skipped, primitives are stringified.
 */
export interface SamlReleasedAttribute {
  name: string;
  value: string;
}

/** SAML names use the full attribute URNs (NameFormat `uri`). */
export function samlAttributeNames(env: Env): {
  accountId: string;
  accountName: string;
  accountRole: string;
  attributePrefix: string;
} {
  const namespace = claimNamespace(env);
  return {
    accountId: `${namespace}/${ACTIVE_ACCOUNT_CLAIM_SUFFIX}-id`,
    accountName: `${namespace}/${ACTIVE_ACCOUNT_CLAIM_SUFFIX}-name`,
    accountRole: `${namespace}/${ACTIVE_ACCOUNT_CLAIM_SUFFIX}-role`,
    attributePrefix: `${namespace}/${ATTRIBUTES_CLAIM_SUFFIX}`,
  };
}

function attributeValue(attributes: Record<string, AttributeValue>, key: string): string | null {
  const value = attributes[key];
  if (value === null) return null;
  return String(value);
}

export async function samlAttributeRelease(
  env: Env,
  sessionToken: string | null,
  sessionId: string | null,
  userId: string | null,
  subject?: string,
): Promise<SamlReleasedAttribute[]> {
  if (!accountClaimsEnabled(env) && !attributeClaimsEnabled(env)) return [];
  const names = samlAttributeNames(env);
  const attributes: SamlReleasedAttribute[] = [];
  if (accountClaimsEnabled(env) && sessionToken && sessionId &&
      (await claimReleaseDecision(env, subject, "account"))) {
    const context = await getSessionAccountContext(env, sessionId);
    if (context) {
      attributes.push(
        { name: names.accountId, value: context.account.id },
        { name: names.accountName, value: context.account.name },
        { name: names.accountRole, value: context.role },
      );
      if (await claimReleaseDecision(env, subject, "accountAttributes")) {
        const accountAttributes = await getObjectAttributes(env, "account", context.account.id);
        for (const key of Object.keys(accountAttributes.attributes).sort()) {
          const value = attributeValue(accountAttributes.attributes, key);
          if (value !== null) {
            attributes.push({ name: `${names.attributePrefix}-account/${key}`, value });
          }
        }
      }
    }
  }
  if (attributeClaimsEnabled(env) && userId && (await claimReleaseDecision(env, subject, "attributes"))) {
    const userAttributes = await getObjectAttributes(env, "user", userId);
    const filtered = await userAttributesForSubject(env, subject, userAttributes.attributes);
    for (const key of Object.keys(filtered).sort()) {
      const value = attributeValue(filtered, key);
      if (value !== null) {
        attributes.push({ name: `${names.attributePrefix}/${key}`, value });
      }
    }
  }
  // Group attributes ride on the attribute claim: the acting user's own
  // groups, keyed by group id in the attribute name.
  if (attributeClaimsEnabled(env) && userId && (await claimReleaseDecision(env, subject, "groupAttributes"))) {
    const groupBundle = await groupAttributesClaimForSubject(env, userId, subject);
    const bundle = groupBundle[`${claimNamespace(env)}/group-attributes`];
    if (bundle && typeof bundle === "object") {
      for (const [groupId, groupAttributes] of Object.entries(bundle as Record<string, unknown>)) {
        if (!groupAttributes || typeof groupAttributes !== "object") continue;
        for (const key of Object.keys(groupAttributes).sort()) {
          const value = attributeValue(groupAttributes as Record<string, AttributeValue>, key);
          if (value !== null) {
            attributes.push({ name: `${names.attributePrefix}-group/${groupId}/${key}`, value });
          }
        }
      }
    }
  }
  return attributes.sort((left, right) => left.name.localeCompare(right.name));
}

/**
 * JWT plugin payload release. The plugin replaces the payload wholesale, so
 * the built-in behavior (the entire user object) is preserved by spreading
 * `user` first; released claims are additive keys.
 */
export async function jwtPayloadRelease(
  env: Env,
  session: { user: { id: string } } & Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!accountClaimsEnabled(env) && !attributeClaimsEnabled(env)) return { ...session.user };
  const sessionId = typeof (session as { session?: { id?: unknown } }).session?.id === "string"
    ? ((session as { session?: { id: string } }).session?.id ?? null)
    : null;
  return {
    ...session.user,
    ...(await oidcClaimRelease(env, sessionId, session.user?.id)),
  };
}
