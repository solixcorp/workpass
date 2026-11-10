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
 * Everything fails closed: without the operator flags the helpers return
 * empty claims and the surfaces are byte-identical to pre-release behavior.
 * Only the acting user's attributes are released; group attributes stay
 * unreleased pending a per-application release policy.
 */

import type { Env } from "../env";
import { getObjectAttributes, type AttributeValue } from "../objects/attributes";
import { getSessionAccountContext } from "../accounts/store";
import { claimReleaseDecision } from "./release-policy";

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
  if (Object.keys(attributes).length === 0) return {};
  return { [`${claimNamespace(env)}/${ATTRIBUTES_CLAIM_SUFFIX}`]: attributes };
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
    ...(await userAttributesClaimForSubject(env, userId, subject)),
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
    }
  }
  if (attributeClaimsEnabled(env) && userId && (await claimReleaseDecision(env, subject, "attributes"))) {
    const userAttributes = await getObjectAttributes(env, "user", userId);
    for (const key of Object.keys(userAttributes.attributes).sort()) {
      const value = attributeValue(userAttributes.attributes, key);
      if (value !== null) {
        attributes.push({ name: `${names.attributePrefix}/${key}`, value });
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
