import type { Env } from "../env";
import type { AuthInstance } from "../auth/config";
import { updateAuditEvent, insertAuditEvent } from "../audit/store";
import { getSessionMfaProof } from "../mfa/second-factor";
import { stepUpUi } from "./step-up-ui";
import { enforceLocationAfterPasskeyLogin } from "./location-gate";
import {
  getStepUpChallenge,
  openStepUpChallenge,
  stepUpChallengeTtlSeconds,
  usableSecondFactors,
} from "./step-up";
import {
  claimAndConsumeFingerprintEvent,
  consumeFingerprintLookupBudget,
  evaluateFingerprintRisk,
  fingerprintBlocksSignIn,
  fingerprintMode,
  isNewDeviceOnly,
  recordFingerprintObservation,
  verifyFingerprintEvent,
} from "./fingerprint";

const riskLoginPaths = new Set([
  "/api/auth/sign-in/email",
  "/api/auth/sign-in/username",
  "/api/auth/passkey/verify-authentication",
]);

// --- Step-up challenge (docs/security/device-risk-and-trust.md) -----------
/**
 * Second-factor verification points record session-bound proofs and satisfy
 * open challenges; the SSO issuance gate below refuses a flagged session
 * until then.
 *
 * Gate order (fail closed):
 * 1. the acting session carries a durable MFA proof → the risk decision was
 *    answered; never challenge a verified session twice,
 * 2. an open, unexpired challenge exists → re-present it,
 * 3. a challenge was satisfied within the retention window → allow,
 * 4. no requirement yet → issue one only when the account can complete it;
 *    otherwise fail closed as before.
 */
type StepUpGate =
  | { action: "allow" }
  | { action: "challenge"; methods: string[] }
  | { action: "deny"; methods: string[] };

interface ActingSession {
  user: { id: string };
  session?: { token?: unknown } | null;
}

function actingSessionToken(session: ActingSession | null): string | null {
  const token = session?.session?.token;
  return typeof token === "string" && token.length > 0 && token.length <= 512 ? token : null;
}

async function evaluateStepUpGate(env: Env, session: ActingSession): Promise<StepUpGate> {
  const sessionToken = actingSessionToken(session);
  if (sessionToken) {
    const proof = await getSessionMfaProof(env, sessionToken).catch(() => null);
    // A passkey sign-in is recorded as a proof for apps that ask for one, but it is the very
    // sign-in this gate is judging, so it cannot answer the risk challenge by itself.
    if (proof && proof.methods.some((method) => method !== "passkey")) return { action: "allow" };
    const challenge = await getStepUpChallenge(env, sessionToken);
    if (challenge.state === "satisfied") return { action: "allow" };
    if (challenge.state === "pending" || challenge.state === "expired") {
      return { action: "challenge", methods: await usableSecondFactors(env, session.user.id) };
    }
  }
  // No requirement bound to this session: challenge only when the account can
  // actually complete the second factor.
  const methods = await usableSecondFactors(env, session.user.id);
  if (methods.length === 0) return { action: "deny", methods: [] };
  return { action: "challenge", methods };
}

/** 403 body presenting the challenge; fail closed when it cannot be recorded. */
async function stepUpChallengeResponseForSession(input: {
  env: Env;
  session: ActingSession;
  reasons: string[];
  requestPath: string;
  gate: StepUpGate;
}): Promise<Response> {
  const sessionToken = actingSessionToken(input.session);
  if (input.gate.action === "deny" || !sessionToken) {
    return Response.json(
      { error: "Additional verification is required before continuing" },
      { status: 403 },
    );
  }
  const methods = input.gate.action === "challenge" ? input.gate.methods : [];
  const opened = await openStepUpChallenge({
    env: input.env,
    sessionToken,
    userId: input.session.user.id,
    reasons: input.reasons,
    requestPath: input.requestPath,
  }).catch(() => false);
  if (!opened) {
    return Response.json({ error: "Step-up verification is unavailable" }, { status: 503 });
  }
  const challenge = await getStepUpChallenge(input.env, sessionToken);
  return Response.json(
    {
      error: "Additional verification is required before continuing",
      challenge: { required: true, methods, expiresAt: challenge.expiresAt, ui: stepUpUi(methods) },
    },
    { status: 403 },
  );
}

/** Attach `stepUpChallenge` to a JSON response; non-JSON bodies pass through. */
async function annotateStepUpChallenge(
  response: Response,
  annotation: { methods: string[]; expiresAt: string | null },
): Promise<Response> {
  try {
    const body = await response.clone().json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return response;
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    return new Response(
      JSON.stringify({
        ...(body as Record<string, unknown>),
        stepUpChallenge: { required: true, ...annotation, ui: stepUpUi(annotation.methods) },
      }),
      { status: response.status, statusText: response.statusText, headers },
    );
  } catch {
    return response;
  }
}


export function isFingerprintRiskLogin(path: string): boolean {
  return riskLoginPaths.has(path);
}

/**
 * A browser that opens the authorize address cannot carry a device event. Send
 * it to the page that collects one (and, when asked, a second factor) and
 * back, instead of showing it raw JSON. Only page navigations are redirected.
 */
function deviceCheckRedirect(env: Env, request: Request, challenge = false): Response | null {
  const isPage = request.method === "GET" &&
    (request.headers.get("sec-fetch-mode") === "navigate" || (request.headers.get("accept") ?? "").includes("text/html"));
  if (!isPage) return null;
  const next = new URL(request.url);
  next.searchParams.delete("fingerprint_event_id");
  const target = new URL("/verify-device", env.AUTH_BASE_URL);
  target.searchParams.set("next", `${next.pathname}${next.search}`);
  if (challenge) target.searchParams.set("challenge", "1");
  return new Response(null, { status: 302, headers: { Location: target.toString(), "Cache-Control": "no-store" } });
}

export function isInteractiveAuthorization(path: string): boolean {
  return path === "/api/auth/oauth2/authorize";
}

export async function handleFingerprintRiskAuthorization(input: {
  request: Request;
  env: Env;
  auth: AuthInstance;
}): Promise<Response | null> {
  // Verdicts no longer stop an authorization; see fingerprintBlocksSignIn.
  if (!fingerprintBlocksSignIn(input.env)) return null;

  try {
    return await handleFingerprintRiskAuthorizationEnabled(input);
  } catch {
    return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
  }
}

async function handleFingerprintRiskAuthorizationEnabled(
  input: { request: Request; env: Env; auth: AuthInstance },
): Promise<Response | null> {

  let session: Awaited<ReturnType<typeof input.auth.api.getSession>>;
  try {
    session = await input.auth.api.getSession({ headers: input.request.headers });
  } catch {
    return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
  }
  if (!session) return null;

  const url = new URL(input.request.url);
  const eventId = url.searchParams.get("fingerprint_event_id");
  if (!eventId) {
    const redirect = deviceCheckRedirect(input.env, input.request);
    if (redirect) return redirect;
  }
  const requestedClient = url.searchParams.get("client_id");
  const appSubject = requestedClient ? `oidc:${requestedClient.slice(0, 200)}` : null;
  let withinBudget = false;
  try {
    withinBudget = await consumeFingerprintLookupBudget({
      env: input.env,
      request: input.request,
      limit: 20,
    });
  } catch {
    withinBudget = false;
  }

  const verification = withinBudget
    ? await verifyFingerprintEvent({ env: input.env, request: input.request, eventId })
    : { event: null, error: "provider_unavailable" as const };
  if (!verification.event) {
    const recorded = await writeRiskDecision(
      input.env,
      session.user.id,
      eventId,
      "deny",
      [verification.error ?? "lookup_rate_limited"],
      url.pathname,
      appSubject,
    );
    if (!recorded) {
      return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
    }
    return Response.json({ error: "Additional device verification is required" }, { status: 403 });
  }

  const claimed = await claimAndConsumeFingerprintEvent({
    env: input.env,
    eventId: verification.event.eventId,
    userId: session.user.id,
    context: url.pathname,
  });
  if (!claimed) {
    const recorded = await writeRiskDecision(
      input.env,
      session.user.id,
      eventId,
      "deny",
      ["replayed_event"],
      url.pathname,
      appSubject,
    );
    if (!recorded) {
      return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
    }
    return Response.json({ error: "Additional device verification is required" }, { status: 403 });
  }

  const risk = await evaluateFingerprintRisk({
    env: input.env,
    userId: session.user.id,
    event: verification.event,
  });
  const effectiveAction = risk.action;
  const recorded = await writeRiskDecision(
    input.env,
    session.user.id,
    verification.event.eventId,
    effectiveAction,
    risk.reasons,
    url.pathname,
    appSubject,
  );
  if (!recorded) {
    return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
  }
  if (effectiveAction !== "allow") {
    if (effectiveAction === "deny") {
      return Response.json({ error: "Authentication could not be completed" }, { status: 403 });
    }
    // step_up: the session continues after a second factor is verified; SSO
    // issuance stays withheld until then.
    if (isNewDeviceOnly(risk.reasons) && (await usableSecondFactors(input.env, session.user.id)).length === 0) return null;
    const gate = await evaluateStepUpGate(input.env, session);
    if (gate.action === "allow") return null;
    const challengeResponse = await stepUpChallengeResponseForSession({
      env: input.env,
      session,
      reasons: risk.reasons,
      requestPath: url.pathname,
      gate,
    });
    if (gate.action === "challenge" && challengeResponse.status === 403) {
      const redirect = deviceCheckRedirect(input.env, input.request, true);
      if (redirect) return redirect;
    }
    return challengeResponse;
  }
  return null;
}

export async function handleFingerprintRiskLogin(
  request: Request,
  env: Env,
  auth: AuthInstance,
  eventType: string,
  onVisitorDigest?: (digest: string | null) => void,
): Promise<Response> {
  const mode = fingerprintMode(env);
  // The verdict is still read and recorded; it only refuses or challenges when blocking is on.
  const enforcing = fingerprintBlocksSignIn(env);
  const path = new URL(request.url).pathname;
  const auditId = crypto.randomUUID();

  try {
    await insertAuditEvent(env, {
      id: auditId,
      actor_user_id: null,
      target_user_id: null,
      event_type: eventType,
      outcome: "started",
      request_path: path,
    });
  } catch {
    return Response.json({ error: "Audit event could not be recorded" }, { status: 503 });
  }

  let eventId: string | null = null;
  try {
    const body = (await request.clone().json()) as {
      fingerprint?: { event_id?: unknown; sealed_result?: unknown };
    } | null;
    const fingerprint = body?.fingerprint;
    if (fingerprint && typeof fingerprint === "object") {
      if (typeof fingerprint.event_id === "string") eventId = fingerprint.event_id;
      if (fingerprint.sealed_result !== undefined) {
        await finalizeAudit(env, auditId, null, null, "failure");
        return Response.json(
          { error: "Sealed Fingerprint results are not configured; use event_id" },
          { status: 400 },
        );
      }
    }
  } catch {
    // Better Auth will return its regular malformed-body response.
  }

  let verifiedEvent = null;
  let signalError: string | null = null;
  let eventClaimed = false;
  // Step-up challenge opened in enforce mode for this login, annotated onto
  // the final response when the audit finalizes successfully.
  let pendingStepUpAnnotation: { methods: string[]; expiresAt: string | null } | null = null;
  if (mode !== "disabled") {
    let withinBudget = false;
    try {
      withinBudget = await consumeFingerprintLookupBudget({ env, request, limit: 10 });
    } catch {
      signalError = "lookup_budget_unavailable";
    }
    if (!withinBudget) {
      signalError = signalError ?? "lookup_rate_limited";
    }

    const verification = withinBudget
      ? await verifyFingerprintEvent({ env, request, eventId })
      : { event: null, error: "provider_unavailable" as const };
    if (withinBudget && verification.event) {
      verifiedEvent = verification.event;
    } else if (withinBudget) {
      signalError = verification.error ?? "invalid_event";
    }

    if (enforcing && !verifiedEvent) {
      await finalizeAudit(env, auditId, null, null, "failure");
      const decisionRecorded = await writeRiskDecision(
        env,
        null,
        eventId,
        "deny",
        [signalError ?? "missing_event"],
        path,
      );
      if (!decisionRecorded) {
        return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
      }
      return Response.json(
        { error: "Additional device verification is required" },
        { status: 403 },
      );
    }

    if (verifiedEvent) {
      try {
        eventClaimed = await claimAndConsumeFingerprintEvent({
          env,
          eventId: verifiedEvent.eventId,
          context: path,
        });
        if (!eventClaimed) signalError = "replayed_event";
      } catch {
        signalError = "event_claim_unavailable";
      }
      if (enforcing && !eventClaimed) {
        await finalizeAudit(env, auditId, null, null, "failure");
        const decisionRecorded = await writeRiskDecision(
          env,
          null,
          verifiedEvent.eventId,
          "deny",
          [signalError ?? "replayed_event"],
          path,
        );
        if (!decisionRecorded) {
          return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
        }
        return Response.json({ error: "Additional device verification is required" }, { status: 403 });
      }
    }

  }

  let authResponse: Response;
  try {
    authResponse = await auth.handler(request);
  } catch {
    await finalizeAudit(env, auditId, null, null, "failure");
    return Response.json({ error: "Authentication operation failed" }, { status: 500 });
  }

  const authSucceeded = authResponse.ok ||
    (authResponse.status >= 300 && authResponse.status < 400);
  if (!authSucceeded) {
    await finalizeAudit(env, auditId, null, null, "failure");
    if (mode !== "disabled" && signalError) {
      await writeRiskDecision(env, null, eventId, "observe", [signalError], path);
    }
    return authResponse;
  }

  let responseBody: Record<string, unknown> = {};
  try {
    const value = await authResponse.clone().json();
    if (value && typeof value === "object") responseBody = value as Record<string, unknown>;
  } catch {
    // A successful interactive login should include user/session data, but do not log response material.
  }
  const userValue = responseBody.user;
  let userId = userValue && typeof userValue === "object" &&
    typeof (userValue as { id?: unknown }).id === "string"
    ? (userValue as { id: string }).id
    : null;
  const sessionValue = responseBody.session;
  let sessionToken = typeof responseBody.token === "string"
    ? responseBody.token
    : sessionValue && typeof sessionValue === "object" &&
        typeof (sessionValue as { token?: unknown }).token === "string"
      ? (sessionValue as { token: string }).token
      : null;

  if ((mode !== "disabled" || path === "/api/auth/passkey/verify-authentication") && authSucceeded && (!sessionToken || !userId)) {
    try {
      const sessionFromCookie = await findNewSessionFromResponse(env, authResponse);
      sessionToken = sessionToken ?? sessionFromCookie?.token ?? null;
      userId = userId ?? sessionFromCookie?.userId ?? null;
    } catch {
      if (enforcing) {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
      }
      signalError = signalError ?? "session_lookup_unavailable";
    }
  }

  if (path === "/api/auth/passkey/verify-authentication") {
    try {
      const issued = await findNewSessionFromResponse(env, authResponse);
      if (issued) {
        sessionToken = issued.token;
        userId = issued.userId;
      } else if (sessionToken) {
        const stored = await env.DB.prepare('SELECT token, "userId" FROM "session" WHERE token = ? LIMIT 1')
          .bind(sessionToken).first<{ token: string; userId: string }>();
        if (!stored || (userId && stored.userId !== userId)) throw new Error("Session mismatch");
        userId = stored.userId;
      }
    } catch {
      await finalizeAudit(env, auditId, userId, null, "failure");
      return Response.json({ error: "Session verification is unavailable" }, { status: 503 });
    }
    if (!userId || !sessionToken) {
      await finalizeAudit(env, auditId, userId, null, "failure");
      return Response.json({ error: "Session verification is unavailable" }, { status: 503 });
    }
    const denied = await enforceLocationAfterPasskeyLogin(env, request, authResponse, userId, path, sessionToken);
    if (denied) {
      await finalizeAudit(env, auditId, userId, null, "failure");
      return denied;
    }
  }

  if (enforcing && (!userId || !sessionToken)) {
    if (sessionToken) await revokeNewSession(env, sessionToken);
    await finalizeAudit(env, auditId, userId, null, "failure");
    return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
  }

  if (verifiedEvent && eventClaimed && userId) {
    try {
      const risk = await evaluateFingerprintRisk({ env, userId, event: verifiedEvent });
      onVisitorDigest?.(risk.visitorDigest);
      const effectiveAction = risk.action;
      let decisionRecorded = true;
      decisionRecorded = await writeRiskDecision(
        env,
        userId,
        verifiedEvent.eventId,
        effectiveAction,
        risk.reasons,
        path,
      );

      if (enforcing && !decisionRecorded) {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
      }

      if (enforcing && effectiveAction === "deny") {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json({ error: "Authentication could not be completed" }, { status: 403 });
      }
      if (enforcing && effectiveAction === "step_up" && sessionToken) {
        // The session is issued, but SSO issuance stays withheld until the
        // user completes a second factor (gate lives at the authorize path).
        const methods = await usableSecondFactors(env, userId!);
        if (methods.length === 0 && isNewDeviceOnly(risk.reasons)) {
          // Nothing to challenge with and nothing beyond a new device: sign-in continues.
        } else if (methods.length === 0) {
          await revokeNewSession(env, sessionToken);
          await finalizeAudit(env, auditId, userId, null, "failure");
          return Response.json({ error: "Additional verification is required before signing in" }, { status: 403 });
        }
        const opened = await openStepUpChallenge({
          env,
          sessionToken,
          userId: userId!,
          reasons: risk.reasons,
          requestPath: path,
        }).catch(() => false);
        if (!opened) {
          await revokeNewSession(env, sessionToken);
          await finalizeAudit(env, auditId, userId, null, "failure");
          return Response.json({ error: "Step-up verification is unavailable" }, { status: 503 });
        }
        const challenge = await getStepUpChallenge(env, sessionToken);
        pendingStepUpAnnotation = { methods, expiresAt: challenge.expiresAt };
      }
      await recordFingerprintObservation({ env, userId, event: verifiedEvent, risk });
      await bindFingerprintEventUser(env, verifiedEvent.eventId, userId);
    } catch {
      if (enforcing) {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
      }
    }
  } else if (mode !== "disabled") {
    if (verifiedEvent && enforcing) {
      if (sessionToken) await revokeNewSession(env, sessionToken);
      await finalizeAudit(env, auditId, userId, null, "failure");
      return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
    }
    const decisionRecorded = await writeRiskDecision(
      env,
      userId,
      eventId,
      "observe",
      [signalError ?? "event_not_bound_to_user"],
      path,
    );
    if (enforcing && !decisionRecorded) {
      if (sessionToken) await revokeNewSession(env, sessionToken);
      await finalizeAudit(env, auditId, userId, null, "failure");
      return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
    }
  }

  const auditFinalized = await finalizeAudit(env, auditId, userId, null, "success");
  if (!auditFinalized) {
    if (sessionToken) await revokeNewSession(env, sessionToken);
    return Response.json({ error: "Authentication audit could not be finalized" }, { status: 503 });
  }
  if (pendingStepUpAnnotation) {
    return annotateStepUpChallenge(authResponse, pendingStepUpAnnotation);
  }
  return authResponse;
}

async function revokeNewSession(env: Env, token: string): Promise<void> {
  await env.DB.prepare('DELETE FROM "session" WHERE token = ?').bind(token).run();
}

async function bindFingerprintEventUser(env: Env, eventId: string, userId: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE fingerprint_event_claims SET user_id = ?
     WHERE event_id = ? AND user_id IS NULL AND consumed_at IS NOT NULL`,
  )
    .bind(userId, eventId)
    .run();
}

export async function findNewSessionFromResponse(
  env: Env,
  response: Response,
): Promise<{ token: string; userId: string } | null> {
  let cookies: string[] = [];
  if (typeof response.headers.getSetCookie === "function") {
    cookies = response.headers.getSetCookie();
  } else {
    const header = response.headers.get("set-cookie");
    if (header) cookies = header.split(/,(?=\s*(?:__Secure-|__Host-|better-auth\.)?[^;,]+=)/g);
  }

  for (const cookie of cookies) {
    const separator = cookie.indexOf("=");
    if (separator < 0) continue;
    const name = cookie.slice(0, separator).trim();
    if (!name.endsWith("session_token")) continue;
    const rawValue = cookie.slice(separator + 1).split(";", 1)[0]?.trim();
    if (!rawValue) continue;
    let decodedValue: string;
    try {
      decodedValue = decodeURIComponent(rawValue);
    } catch {
      continue;
    }
    const token = decodedValue.split(".", 1)[0];
    if (!token) continue;
    const session = await env.DB.prepare(
      'SELECT token, "userId" FROM "session" WHERE token = ? LIMIT 1',
    )
      .bind(token)
      .first<{ token: string; userId: string }>();
    if (session) return session;
  }
  return null;
}

async function finalizeAudit(
  env: Env,
  auditId: string,
  actorUserId: string | null,
  targetUserId: string | null,
  outcome: "success" | "failure",
): Promise<boolean> {
  try {
    await updateAuditEvent(env, auditId, {
      actor_user_id: actorUserId,
      target_user_id: targetUserId,
      outcome,
    });
    return true;
  } catch {
    // The started record is retained for reconciliation; the caller still withholds risk-denied sessions.
    return false;
  }
}

export async function writeRiskDecision(
  env: Env,
  userId: string | null,
  _providerEventId: string | null,
  action: "allow" | "step_up" | "deny" | "observe",
  reasons: string[],
  requestPath: string,
  subject: string | null = null,
): Promise<boolean> {  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const safeReasons = JSON.stringify(reasons.slice(0, 12));
  try {
    await env.DB.prepare(
      `INSERT INTO fingerprint_risk_decisions
        (id, user_id, event_id, action, reasons, request_path, occurred_at, subject)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(id, userId, null, action, safeReasons, requestPath, now, subject)
      .run();
    await insertAuditEvent(env, {
      id: crypto.randomUUID(),
      actor_user_id: userId,
      target_user_id: userId,
      event_type: `authentication.fingerprint.risk_${action}`,
      outcome: action === "deny" ? "failure" : "success",
      request_path: requestPath,
    });
    await env.DB.prepare(
      "DELETE FROM fingerprint_risk_decisions WHERE occurred_at < ?",
    )
      .bind(new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString())
      .run();
    return true;
  } catch {
    return false;
  }
}
