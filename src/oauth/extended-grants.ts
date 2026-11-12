/**
 * Token grant handlers for the extended grants, registered through the
 * oauthProvider `extensions[].grants` surface (same pattern as RFC 8693 token
 * exchange in src/token/grant.ts):
 *
 * - RFC 8628 `urn:ietf:params:oauth:grant-type:device_code` (device flow,
 *   docs/design/device-flow.md),
 * - OpenID CIBA poll mode `urn:openid:params:grant-type:ciba`
 *   (docs/design/ciba.md).
 *
 * Both grants poll the same state machine: pending → authorization_pending
 * (slow_down on fast polls) → approved → single-use issuance, denied →
 * access_denied, expired → invalid_grant/expired_token. Client authentication
 * delegates to the provider (all built-in methods); public-device clients must
 * still be registered for the grant. Every issuance is audited and the acting
 * user's ban state is re-checked at the token moment.
 */

import { APIError } from "better-auth/api";
import type { OAuthProviderExtension, OAuthExtensionGrantHandlerInput, SchemaClient, Scope } from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { checkOidcAccess } from "../access/oidc-gate";
import {
  consumeDeviceGrant, deviceGrantPollIntervalViolated, loadDeviceGrantByCode, DEVICE_CODE_GRANT,
} from "./device-flow";
import {
  consumeCibaRequest, cibaPollIntervalViolated, loadCibaRequest, CIBA_GRANT,
} from "./ciba";

function reject(error: string, description?: string): never {
  throw new APIError("BAD_REQUEST", { error, error_description: description });
}

function invalid(error: string): never {
  throw new APIError("BAD_REQUEST", { error, error_description: "Authorization request rejected" });
}

/** Client registrations carry `grantTypes`; a client without the grant on its
 * registration is denied even though the server advertises the grant. */
function clientAllowsGrant(client: { grantTypes?: string[] }, grantType: string): boolean {
  const allowed = client.grantTypes && client.grantTypes.length > 0 ? client.grantTypes : ["authorization_code"];
  return allowed.includes(grantType);
}

/** Shared poll state machine. Returns the response for the grant issuer. */
type GrantState = { kind: "issue"; userId: string; sessionId: string; scopes: string[]; consume: () => Promise<boolean> };

async function pollState(env: Env, state: {
  status: "pending" | "approved" | "denied" | "consumed";
  userId: string | null;
  sessionId: string | null;
  scopes: string[];
  intervalViolated: boolean;
  consume: () => Promise<boolean>;
}): Promise<GrantState> {
  if (state.intervalViolated) invalid("slow_down");
  if (state.status === "pending") invalid("authorization_pending");
  if (state.status === "denied") reject("access_denied", "The end user denied the request");
  if (state.status !== "approved") invalid("invalid_grant");
  if (!state.userId || !state.sessionId) invalid("invalid_grant"); // corrupt row: fail closed
  return { kind: "issue", userId: state.userId, sessionId: state.sessionId, scopes: state.scopes, consume: state.consume };
}

async function issueForUser(
  env: Env,
  input: OAuthExtensionGrantHandlerInput,
  client: SchemaClient<Scope[]>,
  state: GrantState,
  auditEvent: Parameters<typeof insertAuditEvent>[1]["event_type"],
  requestPath: string,
) {
  const account = await env.DB.prepare('SELECT banned FROM "user" WHERE id = ? LIMIT 1')
    .bind(state.userId).first<{ banned: number | null }>();
  if (!account || (account.banned !== 0 && account.banned !== null)) return invalid("invalid_grant");
  try {
    const row = await env.DB.prepare('SELECT token, "userId", "expiresAt" FROM "session" WHERE id = ? LIMIT 1')
      .bind(state.sessionId).first<{ token: string; userId: string; expiresAt: string | number }>();
    const expires = typeof row?.expiresAt === "number"
      ? (row.expiresAt < 100_000_000_000 ? row.expiresAt * 1000 : row.expiresAt)
      : Date.parse(row?.expiresAt ?? "");
    if (!row || row.userId !== state.userId || !Number.isFinite(expires) || expires <= Date.now()) return invalid("invalid_grant");
    const policyUser = await env.DB.prepare('SELECT role FROM "user" WHERE id = ? LIMIT 1')
      .bind(state.userId).first<{ role: string | null }>();
    if (!policyUser) return invalid("invalid_grant");
    const denied = await checkOidcAccess(env, client.clientId, { user: { id: state.userId, role: policyUser.role }, session: { token: row.token } });
    if (denied) return invalid("access_denied");
  } catch (error) {
    if (error instanceof APIError) throw error;
    throw new APIError("SERVICE_UNAVAILABLE", { error: "temporarily_unavailable", error_description: "Authorization policy unavailable" });
  }
  const user = await input.ctx.context.internalAdapter.findUserById(state.userId);
  if (!user) return invalid("invalid_grant");
  // Policy/MFA failures must leave the one-time grant retryable. The conditional
  // UPDATE still checks approved status and expiry and admits only one redeemer.
  // Policy can change between this check and consumption (bounded TOCTOU);
  // policy evaluation and grant consumption do not share a DB transaction.
  if (!(await state.consume())) return invalid("invalid_grant");
  // Before issuance: if audit is unavailable, do not mint a token (the same
  // discipline as the token-exchange grant).
  await insertAuditEvent(env, { id: crypto.randomUUID(), actor_user_id: state.userId,
    target_user_id: state.userId, event_type: auditEvent, outcome: "success", request_path: requestPath });
  return await input.provider.issueTokens({ client, user, scopes: state.scopes, sessionId: state.sessionId });
}

/** RFC 8628 §3.4 token request. Public clients authenticate with client_id
 * only; confidential clients must present credentials. */
export async function handleDeviceCodeGrant(env: Env, input: OAuthExtensionGrantHandlerInput) {
  if (env.ENABLE_DEVICE_FLOW !== "true") return invalid("unauthorized_client");
  const body = input.ctx.body as Record<string, unknown>;
  const allowedFields = new Set(["grant_type", "device_code", "client_id", "client_secret", "client_assertion", "client_assertion_type"]);
  if (Object.keys(body).some((key) => !allowedFields.has(key)) ||
      typeof body.device_code !== "string" || body.device_code.length < 16 || body.device_code.length > 512) {
    return invalid("invalid_request");
  }
  // Public devices authenticate with client_id alone; the registered auth
  // method decides whether credentials are mandatory.
  const registered = body.client_id !== undefined && typeof body.client_id === "string"
    ? await input.ctx.context.adapter.findOne<Record<string, unknown>>({ model: "oauthClient",
        where: [{ field: "clientId", value: body.client_id }] })
    : null;
  const isPublic = registered?.tokenEndpointAuthMethod === "none";
  const { client } = await input.provider.authenticateClient({ requireCredentials: !isPublic });
  if (!clientAllowsGrant(client, DEVICE_CODE_GRANT)) return invalid("unauthorized_client");
  const deviceCode: string = body.device_code;
  const grant = await loadDeviceGrantByCode(env, deviceCode);
  if (!grant || grant.clientId !== client.clientId) return invalid("invalid_grant");
  const state = await pollState(env, {
    status: grant.status, userId: grant.userId, sessionId: grant.sessionId, scopes: grant.scopes,
    intervalViolated: await deviceGrantPollIntervalViolated(env, deviceCode, grant.intervalSeconds),
    consume: () => consumeDeviceGrant(env, deviceCode),
  });
  return await issueForUser(env, input, client, state, "authentication.device_flow.token_issued",
    "/api/auth/oauth2/token");
}

/** CIBA poll-mode token request (§10). Clients authenticate confidentially. */
export async function handleCibaGrant(env: Env, input: OAuthExtensionGrantHandlerInput) {
  if (env.ENABLE_CIBA !== "true") return invalid("unauthorized_client");
  const body = input.ctx.body as Record<string, unknown>;
  const allowedFields = new Set(["grant_type", "auth_req_id", "client_id", "client_secret", "client_assertion", "client_assertion_type"]);
  if (Object.keys(body).some((key) => !allowedFields.has(key)) ||
      typeof body.auth_req_id !== "string" || body.auth_req_id.length < 16 || body.auth_req_id.length > 512) {
    return invalid("invalid_request");
  }
  // CIBA §1: clients must authenticate confidentially.
  const { client } = await input.provider.authenticateClient({ requireCredentials: true });
  if (client.tokenEndpointAuthMethod === "none" || !clientAllowsGrant(client, CIBA_GRANT)) {
    return invalid("unauthorized_client");
  }
  const authReqId: string = body.auth_req_id;
  const request = await loadCibaRequest(env, authReqId);
  if (!request || request.clientId !== client.clientId) return invalid("invalid_grant");
  const state = await pollState(env, {
    status: request.status, userId: request.userId, sessionId: request.sessionId, scopes: request.scopes,
    intervalViolated: await cibaPollIntervalViolated(env, authReqId, request.intervalSeconds),
    consume: () => consumeCibaRequest(env, authReqId),
  });
  return await issueForUser(env, input, client, state, "authentication.ciba.token_issued",
    "/api/auth/oauth2/token");
}

/** Discovery contribution: the backchannel/device authorization endpoints and
 * CIBA's poll delivery mode. Grant types are advertised automatically from the
 * registered extensions. */
export function deviceFlowExtension(env: Env): OAuthProviderExtension {
  return {
    grants: { [DEVICE_CODE_GRANT]: (input) => handleDeviceCodeGrant(env, input) },
    metadata: ({ ctx }) => ({
      device_authorization_endpoint: `${ctx.context.baseURL}/oauth2/device/authorize`,
    }),
  };
}

export function cibaExtension(env: Env): OAuthProviderExtension {
  return {
    grants: { [CIBA_GRANT]: (input) => handleCibaGrant(env, input) },
    metadata: ({ ctx }) => ({
      backchannel_authentication_endpoint: `${ctx.context.baseURL}/oauth2/bc-authorize`,
      backchannel_token_delivery_modes_supported: ["poll"],
    }),
  };
}
