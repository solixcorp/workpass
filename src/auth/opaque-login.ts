/**
 * The OPAQUE login gate, applied after the cryptography succeeds and BEFORE
 * the session issues. It restores parity with the password/username/passkey
 * login paths that Better Auth + the risk middleware already cover:
 *
 * 1. Account state: a banned account (or one whose row cannot be read) is
 *    denied — enrollment keys must never resurrect a disabled identity.
 * 2. Device risk: whenever FINGERPRINT_SERVER_API_KEY is set (and
 *    FINGERPRINT_BREAK_GLASS is not), the fingerprint event the client
 *    submitted at /auth/start is verified, claimed (single use) and
 *    risk-evaluated here. The session is withheld on deny and on any
 *    missing or unverifiable event; a `step_up` decision issues the session
 *    with a step-up challenge when the account has an enrollable second
 *    factor (src/security/step-up.ts). Without one, a device that is merely
 *    new (isNewDeviceOnly) still signs in; any stronger reason is denied.
 *
 * Decisions are recorded through the shared risk-decision writer so the
 * OPAQUE surface audits exactly like the other login flows.
 */

import type { Env } from "../env";
import {
  claimAndConsumeFingerprintEvent,
  consumeFingerprintLookupBudget,
  evaluateFingerprintRisk,
  fingerprintMode,
  isNewDeviceOnly,
  type FingerprintRisk,
  recordFingerprintObservation,
  verifyFingerprintEvent,
} from "../security/fingerprint";
import { writeRiskDecision } from "../security/risk-auth-middleware";
import { usableSecondFactors } from "../security/step-up";

export interface OpaqueLoginGateInput {
  /** The acting user, when the login identified one. */
  userId: string | null;
  /** The fingerprint event id submitted at /auth/start, if any. */
  eventId: string | null;
  /** The finish request, for lookup budgets and origin checks. */
  request: Request;
  contextPath: string;
}

export type OpaqueLoginDecision = {
  allowed: boolean;
  action: "allow" | "step_up" | "deny";
  reasons: string[];
  visitorDigest?: string | null;
};

async function recordDecision(
  env: Env,
  userId: string | null,
  eventId: string | null,
  action: "allow" | "step_up" | "deny" | "observe",
  reasons: string[],
  contextPath: string,
): Promise<void> {
  try {
    await writeRiskDecision(env, userId, eventId, action, reasons, contextPath);
  } catch {
    // Decision recording is best-effort here; the caller treats gate
    // denials as final regardless.
  }
}

export async function evaluateOpaqueLoginGate(env: Env, input: OpaqueLoginGateInput): Promise<OpaqueLoginDecision> {
  const reasons: string[] = [];

  // 1. Account state — fail closed when the row cannot be read at all.
  if (input.userId) {
    const account = await env.DB.prepare(
      'SELECT banned FROM "user" WHERE id = ? LIMIT 1',
    ).bind(input.userId).first<{ banned: number | null }>().catch(() => null);
    if (!account) return { allowed: false, action: "deny", reasons: ["account_unavailable"] };
    if (account.banned === 1) return { allowed: false, action: "deny", reasons: ["account_disabled"] };
  }

  if (fingerprintMode(env) === "disabled") return { allowed: true, action: "allow", reasons };

  // 2. Device risk: the shared login pipeline.
  let withinBudget = false;
  try {
    withinBudget = await consumeFingerprintLookupBudget({ env, request: input.request, limit: 10 });
  } catch {
    withinBudget = false;
  }
  if (!withinBudget) reasons.push("lookup_rate_limited");

  const verified = withinBudget && input.eventId
    ? await verifyFingerprintEvent({ env, request: input.request, eventId: input.eventId })
    : { event: null, error: input.eventId ? undefined : "missing_event" as const };

  if (!verified.event) {
    reasons.push(verified.error ?? "invalid_event");
    await recordDecision(env, null, input.eventId, "deny", reasons, input.contextPath);
    return { allowed: false, action: "deny", reasons };
  }

  const event = verified.event;
  let claimed = false;
  try {
    claimed = await claimAndConsumeFingerprintEvent({
      env,
      eventId: event.eventId,
      userId: input.userId,
      context: input.contextPath,
    });
  } catch {
    claimed = false;
  }
  if (!claimed) {
    reasons.push("replayed_event");
    await recordDecision(env, null, event.eventId, "deny", reasons, input.contextPath);
    return { allowed: false, action: "deny", reasons };
  }

  let risk: FingerprintRisk | null = null;
  try {
    risk = await evaluateFingerprintRisk({ env, userId: input.userId ?? "", event });
  } catch {
    risk = null;
  }
  if (!risk) {
    reasons.push("risk_evaluation_unavailable");
    await recordDecision(env, input.userId, event.eventId, "deny", reasons, input.contextPath);
    return { allowed: false, action: "deny", reasons };
  }

  try {
    await recordFingerprintObservation({ env, userId: input.userId ?? "", event, risk });
  } catch {
    reasons.push("observation_unavailable");
  }

  await recordDecision(env, input.userId, event.eventId, risk.action, [...risk.reasons, ...reasons], input.contextPath);

  if (risk.action !== "allow" || reasons.includes("observation_unavailable")) {
    if (risk.action === "deny" || !input.userId) {
      return { allowed: false, action: "deny", reasons: [...risk.reasons, ...reasons] };
    }
    // Step-up with the challenge flow: the session issues and SSO issuance
    // stays withheld until a second factor is verified, when the account can
    // complete one. Without any factor this stays fail closed (denied).
    return await stepUpOutcome(env, input.userId, [...risk.reasons, ...reasons]);
  }
  return {
    allowed: true,
    action: risk.action,
    reasons: [...risk.reasons, ...reasons],
    visitorDigest: risk.visitorDigest,
  };
}

/**
 * The step-up branch of the gate: challenge-eligible when the account has a
 * usable second factor, otherwise an outright denial. The caller opens the
 * challenge row against the session it is about to issue and annotates the
 * response with `stepUpChallenge` (see src/auth/opaque-routes.ts).
 */
export async function stepUpOutcome(env: Env, userId: string, reasons: string[]): Promise<OpaqueLoginDecision> {
  const methods = await usableSecondFactors(env, userId).catch(() => [] as string[]);
  if (methods.length === 0 && isNewDeviceOnly(reasons)) return { allowed: true, action: "allow", reasons };
  if (methods.length === 0) {
    return { allowed: false, action: "deny", reasons: [...reasons, "no_second_factor"] };
  }
  return { allowed: true, action: "step_up", reasons };
}
