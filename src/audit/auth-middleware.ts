import type { Env } from "../env";
import { createAuth, type AuthInstance } from "../auth/config";
import { insertAuditEvent, updateAuditEvent } from "./store";
import {
  handleFingerprintRiskLogin,
  handleFingerprintRiskAuthorization,
  isInteractiveAuthorization,
  isFingerprintRiskLogin,
} from "../security/risk-auth-middleware";
import { revokeTrustedDevices } from "../security/trusted-device-store";
import { enforceOidcPolicy } from "../access/oidc-gate";
import { recordOAuthGrant } from "../security/app-grants";
import { recordSessionMfaProof } from "../mfa/second-factor";
import { findNewSessionFromResponse } from "../security/risk-auth-middleware";
import { enforceMfaPolicy } from "../mfa/policy";

const auditEventTypes: Record<string, string> = {
  "POST /api/auth/sign-up/email": "identity.user.public_registration.denied",
  "POST /api/auth/sign-in/email": "authentication.password.success_or_failure",
  "POST /api/auth/sign-in/username": "authentication.username.success_or_failure",
  "POST /api/auth/change-password": "identity.user.password_change.success_or_failure",
  "POST /api/auth/sign-out": "authentication.session.sign_out",
  "POST /api/auth/passkey/verify-authentication": "authentication.passkey.success_or_failure",
  "POST /api/auth/passkey/verify-registration": "authentication.passkey.registration.success_or_failure",
  "GET /api/auth/oauth2/authorize": "oauth.authorization.request",
  "POST /api/auth/oauth2/authorize": "oauth.authorization.request",
  "POST /api/auth/oauth2/token": "oauth.token.issue_or_refresh",
  "POST /api/auth/oauth2/revoke": "oauth.token.revoke",
  "POST /api/auth/oauth2/introspect": "oauth.token.introspect",
  "POST /api/auth/oauth2/consent": "oauth.user_consent",
  "POST /api/auth/admin/create-user": "identity.user.create.success_or_failure",
  "POST /api/auth/admin/update-user": "identity.user.update.success_or_failure",
  "POST /api/auth/admin/set-user-password": "identity.user.password_reset.success_or_failure",
  "POST /api/auth/admin/set-role": "identity.user.role_change.success_or_failure",
  "POST /api/auth/admin/ban-user": "identity.user.disable.success_or_failure",
  "POST /api/auth/admin/unban-user": "identity.user.enable.success_or_failure",
  "POST /api/auth/admin/remove-user": "identity.user.remove.success_or_failure",
  "POST /api/auth/admin/revoke-user-sessions": "identity.user.sessions_revoke.success_or_failure",
  "POST /api/auth/admin/revoke-user-session": "identity.user.session_revoke.success_or_failure",
  "POST /api/auth/oauth2/register": "oauth.client.register.success_or_failure",
};

/**
 * The Better Auth endpoints whose success IS a passed second factor. A
 * successful verification returns { token, user } in both the sign-in
 * continuation case (new session issued) and the already-signed-in case
 * (existing session echoed), so the proof binds to the verified session.
 */
const twoFactorVerifyPaths = new Set([
  "/api/auth/two-factor/verify-totp",
  "/api/auth/two-factor/verify-otp",
  "/api/auth/two-factor/verify-backup-code",
]);

function getResponseUserId(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const user = (value as { user?: unknown }).user;
  if (!user || typeof user !== "object") return null;
  const id = (user as { id?: unknown }).id;
  return typeof id === "string" ? id : null;
}

export async function auditAuthRequest(request: Request, env: Env): Promise<Response> {
  const auth = createAuth(env);
  const path = new URL(request.url).pathname;
  const eventType = auditEventTypes[`${request.method} ${path}`];

  const policyRejection = await enforceOidcPolicy(request, env, auth);
  if (policyRejection) return policyRejection;

  if (request.method === "POST" && (path.startsWith("/api/auth/two-factor/") || path.startsWith("/api/auth/passkey/"))) {
    const actor = await auth.api.getSession({ headers: request.headers }).catch(() => null);
    const mfaRejection = await enforceMfaPolicy(request, env, actor);
    if (mfaRejection) return mfaRejection;
  }

  if (request.method === "POST" && twoFactorVerifyPaths.has(path)) {
    return handleTwoFactorVerification(request, env, auth);
  }

  if (request.method === "POST" && path === "/api/auth/sign-up/email") {
    return denyPublicRegistration(request, env, auth, eventType!);
  }

  if (request.method === "POST" && isFingerprintRiskLogin(path)) {
    return handleFingerprintRiskLogin(
      request,
      env,
      auth,
      eventType ?? "authentication.login.success_or_failure",
    );
  }

  if (isInteractiveAuthorization(path)) {
    const riskResponse = await handleFingerprintRiskAuthorization({ request, env, auth });
    if (riskResponse) return riskResponse;
  }

  if (path === "/api/auth/oauth2/register" && eventType) {
    return auditClientRegistration(request, env, auth, eventType);
  }

  // A copy taken before the provider reads the body, for the grant record.
  const grantCopy = path.startsWith("/api/auth/oauth2/") ? request.clone() : null;

  if (!eventType) {
    const answer = await auth.handler(request);
    if (grantCopy && path === "/api/auth/oauth2/continue") {
      const continuing = await auth.api.getSession({ headers: request.headers }).catch(() => null);
      await recordOAuthGrant(env, grantCopy, answer, continuing?.user.id ?? null);
    }
    return answer;
  }

  let targetUserId: string | null = null;
  if (request.method === "POST" && path.startsWith("/api/auth/admin/")) {
    try {
      const body = (await request.clone().json()) as { userId?: unknown };
      targetUserId = typeof body.userId === "string" ? body.userId : null;
    } catch {
      // Bodies can contain credentials; only retain the target identifier.
    }
  }

  let actorUserId: string | null = null;
  try {
    const session = await auth.api.getSession({ headers: request.headers });
    actorUserId = session?.user.id ?? null;
  } catch {
    // Continue so the auth endpoint returns its normal authentication error.
  }

  const eventId = crypto.randomUUID();
  try {
    await insertAuditEvent(env, {
      id: eventId,
      actor_user_id: actorUserId,
      target_user_id: targetUserId,
      event_type: eventType,
      outcome: "started",
      request_path: path,
    });
  } catch {
    return Response.json({ error: "Audit event could not be recorded" }, { status: 503 });
  }

  let response: Response;
  try {
    response = await auth.handler(request);
  } catch {
    try {
      await updateAuditEvent(env, eventId, {
        actor_user_id: actorUserId,
        target_user_id: targetUserId,
        outcome: "failure",
      });
    } catch {
      // Keep the started event for operational reconciliation.
    }
    return Response.json({ error: "Authentication operation failed" }, { status: 500 });
  }
  if (grantCopy) await recordOAuthGrant(env, grantCopy, response, actorUserId);
  if (
    response.ok &&
    (path === "/api/auth/admin/ban-user" ||
      path === "/api/auth/admin/set-user-password" ||
      path === "/api/auth/admin/remove-user" ||
      path === "/api/auth/change-password") &&
    (targetUserId || actorUserId)
  ) {
    try {
      await revokeTrustedDevices(env, targetUserId ?? actorUserId!);
    } catch {
      // The primary mutation already succeeded. Leave the audit event started
      // for operator reconciliation rather than reporting a fully completed operation.
      return Response.json({ error: "Trusted-device revocation failed", eventId }, { status: 503 });
    }
  }
  if (response.ok) {
    try {
      const responseUserId = getResponseUserId(await response.clone().json());
      targetUserId = responseUserId ?? targetUserId;
      if (
        (path.startsWith("/api/auth/sign-in/") ||
          path === "/api/auth/passkey/verify-authentication") &&
        responseUserId
      ) {
        actorUserId = responseUserId;
        targetUserId = null;
      }
    } catch {
      // Some successful endpoints have no JSON body.
    }
  }

  try {
    await updateAuditEvent(env, eventId, {
      actor_user_id: actorUserId,
      target_user_id: targetUserId,
      outcome: response.ok || (response.status >= 300 && response.status < 400)
        ? "success"
        : "failure",
    });
  } catch {
    return Response.json({ error: "Operation audit finalization failed", eventId }, { status: 503 });
  }

  return response;
}

/**
 * A successful two-factor verification records a session-bound MFA proof.
 * Fail closed: an unverifiable verification must not be reported as success,
 * because requireMfa policies honor only durable proofs.
 *
 * Prefer a session issued or rotated by this verification over the echoed
 * body token: the plugin rotates the session on the FIRST verification
 * (new cookie issued, old session row deleted) while the body still carries
 * the rotated-out token. Only tokens that resolve in the session table are
 * recorded.
 */
export async function handleTwoFactorVerification(request: Request, env: Env, auth: AuthInstance): Promise<Response> {
  let response: Response;
  try {
    response = await auth.handler(request);
  } catch {
    return Response.json({ error: "Authentication operation failed" }, { status: 500 });
  }
  if (!response.ok) return response;

  let token: string | null = null;
  let userId: string | null = null;
  try {
    const fromCookie = await findNewSessionFromResponse(env, response);
    token = fromCookie?.token ?? null;
    userId = fromCookie?.userId ?? null;
  } catch {
    // Falls through to the body token below.
  }
  if (!token) {
    try {
      const body = await response.clone().json() as { token?: unknown } | null;
      if (typeof body?.token === "string" && body.token.length > 0 && body.token.length <= 512) {
        token = body.token;
      }
    } catch {
      // Some successful verifications have no JSON body; userId stays null.
    }
  }
  // The proof binds only to a token that really exists in storage.
  if (token && !userId) {
    try {
      userId = await sessionUserIdForToken(env, token);
    } catch {
      userId = null;
    }
  }
  if (!token || !userId || !(await recordSessionMfaProof(env, token, userId))) {
    return Response.json({ error: "The verification could not be recorded" }, { status: 503 });
  }
  return response;
}

/** Resolve the owning user of a session token directly from storage. */
async function sessionUserIdForToken(env: Env, token: string): Promise<string | null> {
  const row = await env.DB.prepare(
    'SELECT "userId" FROM "session" WHERE token = ? LIMIT 1',
  ).bind(token).first<{ userId: string }>();
  return typeof row?.userId === "string" && row.userId.length > 0 && row.userId.length <= 128 ? row.userId : null;
}

async function auditClientRegistration(
  request: Request,
  env: Env,
  auth: AuthInstance,
  eventType: string,
): Promise<Response> {
  let actorUserId: string | null = null;
  try {
    const session = await auth.api.getSession({ headers: request.headers });
    actorUserId = session?.user.id ?? null;
  } catch {
    // The temporary initial-access token may authorize the operation instead.
  }

  const eventId = crypto.randomUUID();
  try {
    await insertAuditEvent(env, {
      id: eventId,
      actor_user_id: actorUserId,
      target_user_id: null,
      event_type: eventType,
      outcome: "started",
      request_path: "/api/auth/oauth2/register",
    });
  } catch {
    return Response.json({ error: "Audit event could not be recorded" }, { status: 503 });
  }

  let response: Response;
  try {
    response = await auth.handler(request);
  } catch {
    try {
      await updateAuditEvent(env, eventId, {
        actor_user_id: actorUserId,
        target_user_id: null,
        outcome: "failure",
      });
    } catch {
      // Keep the started event for later reconciliation.
    }
    return Response.json({ error: "Client registration failed" }, { status: 500 });
  }
  let registeredClientId: string | null = null;
  if (response.ok || response.status === 201) {
    try {
      const body = (await response.clone().json()) as { client_id?: unknown };
      registeredClientId = typeof body.client_id === "string" ? body.client_id : null;
    } catch {
      // Never retain the returned client secret or registration metadata.
    }
  }

  try {
    await updateAuditEvent(env, eventId, {
      actor_user_id: actorUserId,
      target_user_id: registeredClientId,
      outcome: response.ok || response.status === 201 ? "success" : "failure",
    });
  } catch {
    return Response.json({ error: "Operation audit finalization failed", eventId }, { status: 503 });
  }
  return response;
}

async function denyPublicRegistration(
  request: Request,
  env: Env,
  auth: AuthInstance,
  eventType: string,
): Promise<Response> {
  let actorUserId: string | null = null;
  try {
    const session = await auth.api.getSession({ headers: request.headers });
    actorUserId = session?.user.id ?? null;
  } catch {
    // The route is rejected regardless of session state.
  }

  try {
    await insertAuditEvent(env, {
      id: crypto.randomUUID(),
      actor_user_id: actorUserId,
      target_user_id: null,
      event_type: eventType,
      outcome: "failure",
      request_path: "/api/auth/sign-up/email",
    });
  } catch {
    return Response.json({ error: "Audit event could not be recorded" }, { status: 503 });
  }

  return Response.json({ error: "Not Found" }, { status: 404 });
}
