import { APIError } from "better-auth/api";
import type { OAuthProviderExtension, OAuthExtensionGrantHandlerInput } from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { ACCESS_TOKEN_TYPE, authorizeExchange } from "./exchange-authorization";

export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

function reject(error: string): never {
  throw new APIError("BAD_REQUEST", { error, error_description: "Token exchange request rejected" });
}

/** Provider verification validates signature and session binding, but this
 * profile must additionally distinguish an RFC 9068 access token (typ
 * "at+jwt") from an ID token signed with the same key. Opaque tokens are
 * validated by the provider against its own database. */
function isAllowedSubjectTokenFormat(token: string): boolean {
  if (!token.includes(".")) return true;
  const pieces = token.split(".");
  if (pieces.length !== 3 || !/^[A-Za-z0-9_-]+$/.test(pieces[0]!)) return false;
  try {
    const header = JSON.parse(atob(pieces[0]!.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
    return header.typ === "at+jwt" && header.alg === "ES256" && typeof header.kid === "string" && header.kid.length > 0;
  } catch { return false; }
}

/** Configuration is an explicit map of confidential client IDs to allowed
 * resource identifiers. Missing or malformed configuration denies access. */
function allowedResource(config: string | undefined, clientId: string, resource: string): boolean {
  if (!config || config.length > 16384) return false;
  try {
    const parsed: unknown = JSON.parse(config);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    if (!Object.hasOwn(parsed, clientId)) return false;
    const values = (parsed as Record<string, unknown>)[clientId];
    return Array.isArray(values) && values.length > 0 && values.length <= 100 &&
      values.every((value) => typeof value === "string") && values.includes(resource);
  } catch { return false; }
}

export async function handleTokenExchange(
  env: Env,
  { ctx, opts, provider }: OAuthExtensionGrantHandlerInput,
) {
  const body = ctx.body as Record<string, unknown>;
  const allowedFields = new Set(["grant_type", "client_id", "client_secret", "client_assertion", "client_assertion_type", "subject_token", "subject_token_type", "requested_token_type", "resource", "scope"]);
  if (Object.keys(body).some((key) => !allowedFields.has(key)) ||
      typeof body.subject_token !== "string" || !body.subject_token || body.subject_token.length > 8192 ||
      !isAllowedSubjectTokenFormat(body.subject_token) || body.subject_token_type !== ACCESS_TOKEN_TYPE ||
      (body.requested_token_type !== undefined && body.requested_token_type !== ACCESS_TOKEN_TYPE) ||
      typeof body.resource !== "string" || (body.scope !== undefined && typeof body.scope !== "string")) {
    return reject("invalid_request");
  }
  const { client, clientId, confirmation } = await provider.authenticateClient({ requireCredentials: true });
  // This profile cannot preserve a sender constraint on the issued token.
  if (confirmation != null) return reject("invalid_request");
  if (client.tokenEndpointAuthMethod === "none" || !allowedResource(env.TOKEN_EXCHANGE_ALLOWED_RESOURCES, clientId, body.resource)) {
    return reject("invalid_target");
  }
  let token;
  try { token = await provider.requireActiveAccessToken(body.subject_token, clientId); }
  catch { return reject("invalid_request"); }
  // Session-less tokens cannot be reliably invalidated by local offboarding.
  if (typeof token.sid !== "string" || !token.sid) return reject("invalid_request");
  /** The provider computes an issued token's expiry as mint time plus the
   * target resource's configured TTL (falling back to the user default). The
   * output only stays inside the subject's lifetime when that TTL is strictly
   * shorter than the subject's remaining life — this is a configuration-time
   * property, not a per-request override, so it cannot be bypassed. */
  const resourceRow = await ctx.context.adapter
    .findOne<Record<string, unknown>>({ model: "oauthResource", where: [{ field: "identifier", value: body.resource }] });
  const outputTtl = typeof resourceRow?.accessTokenTtl === "number" && resourceRow.accessTokenTtl > 0
    ? resourceRow.accessTokenTtl
    : opts.accessTokenExpiresIn ?? 3600;
  const nowSeconds = Math.floor(Date.now() / 1000);
  // Leave a small margin for the issuer's later clock read.
  const authorized = authorizeExchange({
    clientId,
    subject: { active: token.active === true, clientId: token.client_id, userId: token.sub,
      expiresAt: token.exp, scopes: token.scope, confirmation: token.cnf },
    resource: body.resource, requestedScopes: body.scope as string | undefined,
    // Margin check: the provider expires a minted token at now + outputTtl,
    // so the subject must outlive that by a safe margin.
    outputLifetimeSeconds: outputTtl + 5, nowSeconds,
  });
  if (!authorized) return reject("invalid_request");
  const account = await env.DB.prepare('SELECT banned FROM "user" WHERE id = ? LIMIT 1')
    .bind(authorized.userId).first<{ banned: number | null }>();
  if (!account || (account.banned !== 0 && account.banned !== null)) return reject("invalid_request");
  const user = await ctx.context.internalAdapter.findUserById(authorized.userId);
  if (!user) return reject("invalid_request");
  // Before issuance: if audit is unavailable, do not mint a token.
  await insertAuditEvent(env, { id: crypto.randomUUID(), actor_user_id: authorized.userId,
    target_user_id: authorized.userId, event_type: "authentication.token_exchange.authorized",
    outcome: "success", request_path: "/api/auth/oauth2/token" });
  return provider.issueTokens({ client, user, scopes: authorized.scopes, sessionId: token.sid,
    resources: [body.resource], tokenResponse: { issued_token_type: ACCESS_TOKEN_TYPE } });
}

export function tokenExchangeExtension(env: Env): OAuthProviderExtension {
  return { grants: { [TOKEN_EXCHANGE_GRANT]: (input) => handleTokenExchange(env, input) } };
}
