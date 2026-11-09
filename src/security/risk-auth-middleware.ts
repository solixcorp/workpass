import type { Env } from "../env";
import type { AuthInstance } from "../auth/config";
import { updateAuditEvent, insertAuditEvent } from "../audit/store";
import {
  claimAndConsumeFingerprintEvent,
  consumeFingerprintLookupBudget,
  evaluateFingerprintRisk,
  fingerprintMode,
  recordFingerprintObservation,
  verifyFingerprintEvent,
} from "./fingerprint";

const riskLoginPaths = new Set([
  "/api/auth/sign-in/email",
  "/api/auth/sign-in/username",
  "/api/auth/passkey/verify-authentication",
]);

export function isFingerprintRiskLogin(path: string): boolean {
  return riskLoginPaths.has(path);
}

export function isInteractiveAuthorization(path: string): boolean {
  return path === "/api/auth/oauth2/authorize";
}

export async function handleFingerprintRiskAuthorization(input: {
  request: Request;
  env: Env;
  auth: AuthInstance;
}): Promise<Response | null> {
  const mode = fingerprintMode(input.env);
  if (mode === "disabled") return null;

  try {
    return await handleFingerprintRiskAuthorizationEnabled(input, mode);
  } catch {
    if (mode === "enforce") {
      return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
    }
    return null;
  }
}

async function handleFingerprintRiskAuthorizationEnabled(
  input: { request: Request; env: Env; auth: AuthInstance },
  mode: "observe" | "enforce",
): Promise<Response | null> {

  let session: Awaited<ReturnType<typeof input.auth.api.getSession>>;
  try {
    session = await input.auth.api.getSession({ headers: input.request.headers });
  } catch {
    return mode === "enforce"
      ? Response.json({ error: "Device risk verification is unavailable" }, { status: 503 })
      : null;
  }
  if (!session) return null;

  const url = new URL(input.request.url);
  const eventId = url.searchParams.get("fingerprint_event_id");
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
      mode === "enforce" ? "deny" : "observe",
      [verification.error ?? "lookup_rate_limited"],
      url.pathname,
    );
    if (mode === "enforce" && !recorded) {
      return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
    }
    if (mode === "enforce") {
      return Response.json({ error: "Additional device verification is required" }, { status: 403 });
    }
    return null;
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
      mode === "enforce" ? "deny" : "observe",
      ["replayed_event"],
      url.pathname,
    );
    if (mode === "enforce" && !recorded) {
      return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
    }
    if (mode === "enforce") {
      return Response.json({ error: "Additional device verification is required" }, { status: 403 });
    }
    return null;
  }

  const risk = await evaluateFingerprintRisk({
    env: input.env,
    userId: session.user.id,
    event: verification.event,
  });
  if (mode === "observe") {
    try {
      await recordFingerprintObservation({
        env: input.env,
        userId: session.user.id,
        event: verification.event,
        risk,
      });
    } catch {
      // Observation is best-effort and must not change the authorization response.
    }
  }
  const effectiveAction = risk.action;
  const recorded = await writeRiskDecision(
    input.env,
    session.user.id,
    verification.event.eventId,
    effectiveAction,
    risk.reasons,
    url.pathname,
  );
  if (mode === "enforce" && !recorded) {
    return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
  }
  if (mode === "enforce" && effectiveAction !== "allow") {
    return Response.json(
      {
        error: effectiveAction === "step_up"
          ? "Additional verification is required before continuing"
          : "Authentication could not be completed",
      },
      { status: 403 },
    );
  }
  return null;
}

export async function handleFingerprintRiskLogin(
  request: Request,
  env: Env,
  auth: AuthInstance,
  eventType: string,
): Promise<Response> {
  const mode = fingerprintMode(env);
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

    if (mode === "enforce" && !verifiedEvent) {
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
      if (mode === "enforce" && !eventClaimed) {
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

  if (mode !== "disabled" && authSucceeded && (!sessionToken || !userId)) {
    try {
      const sessionFromCookie = await findNewSessionFromResponse(env, authResponse);
      sessionToken = sessionToken ?? sessionFromCookie?.token ?? null;
      userId = userId ?? sessionFromCookie?.userId ?? null;
    } catch {
      if (mode === "enforce") {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
      }
      signalError = signalError ?? "session_lookup_unavailable";
    }
  }

  if (mode === "enforce" && (!userId || !sessionToken)) {
    if (sessionToken) await revokeNewSession(env, sessionToken);
    await finalizeAudit(env, auditId, userId, null, "failure");
    return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
  }

  if (verifiedEvent && eventClaimed && userId) {
    try {
      const risk = await evaluateFingerprintRisk({ env, userId, event: verifiedEvent });
      const effectiveAction = risk.action;
      let decisionRecorded = true;
      if (mode === "observe" || mode === "enforce") {
        decisionRecorded = await writeRiskDecision(
          env,
          userId,
          verifiedEvent.eventId,
          effectiveAction,
          risk.reasons,
          path,
        );
      }

      if (mode === "enforce" && !decisionRecorded) {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
      }

      if (mode === "enforce" && effectiveAction !== "allow") {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json(
          {
            error: effectiveAction === "step_up"
              ? "Additional verification is required before signing in"
              : "Authentication could not be completed",
          },
          { status: 403 },
        );
      }
      if (mode === "observe") {
        try {
          await recordFingerprintObservation({ env, userId, event: verifiedEvent, risk });
        } catch {
          // Observation is best-effort and must not change authentication in observe mode.
        }
      } else if (mode === "enforce") {
        await recordFingerprintObservation({ env, userId, event: verifiedEvent, risk });
      }
      await bindFingerprintEventUser(env, verifiedEvent.eventId, userId);
    } catch {
      if (mode === "enforce") {
        if (sessionToken) await revokeNewSession(env, sessionToken);
        await finalizeAudit(env, auditId, userId, null, "failure");
        return Response.json({ error: "Device risk verification is unavailable" }, { status: 503 });
      }
      if (mode === "observe") {
        try {
          await writeRiskDecision(env, userId, verifiedEvent.eventId, "observe", ["risk_store_unavailable"], path);
        } catch {
          // Risk recording is best-effort when enforcement is disabled.
        }
      }
    }
  } else if (mode !== "disabled") {
    if (verifiedEvent && mode === "enforce") {
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
    if (mode === "enforce" && !decisionRecorded) {
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
): Promise<boolean> {  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const safeReasons = JSON.stringify(reasons.slice(0, 12));
  try {
    await env.DB.prepare(
      `INSERT INTO fingerprint_risk_decisions
        (id, user_id, event_id, action, reasons, request_path, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(id, userId, null, action, safeReasons, requestPath, now)
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
