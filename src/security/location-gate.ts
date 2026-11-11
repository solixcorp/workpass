import { insertAuditEvent } from "../audit/store";
import type { Env } from "../env";
import { evaluateLocation, type LocationVerdict } from "./location-policy";
import { notifySecurity } from "../users/notifications";
import { findNewSessionFromResponse } from "./risk-auth-middleware";

/**
 * Check a sign-in against the place policy and leave an audit event when it
 * does not pass: `authentication.location.denied` when the policy enforces,
 * `authentication.location.observe` when it only watches. Never throws; if
 * the check cannot be made while the policy enforces, the sign-in is refused.
 */
export async function locationGate(
  env: Env,
  input: { request: Request; userId: string | null; path: string; subject?: string },
): Promise<LocationVerdict> {
  let verdict: LocationVerdict;
  try {
    verdict = await evaluateLocation(env, { request: input.request, userId: input.userId, subject: input.subject });
  } catch {
    return { allowed: false, pass: false, mode: "enforce", method: "none", needsBrowser: false, reason: "no_signal", placeName: null, distanceM: null };
  }
  if (verdict.pass || verdict.mode === "off") return verdict;
  try {
    await insertAuditEvent(env, {
      id: crypto.randomUUID(),
      actor_user_id: input.userId,
      target_user_id: input.userId,
      event_type: verdict.mode === "enforce" ? "authentication.location.denied" : "authentication.location.observe",
      outcome: verdict.mode === "enforce" ? "failure" : "success",
      request_path: input.path,
      client_ip: input.request.headers.get("cf-connecting-ip"),
      event_context: { reason: verdict.reason, nearestPlace: verdict.placeName, distanceM: verdict.distanceM, ...(input.subject ? { subject: input.subject } : {}) },
    });
  } catch {
    // The decision stands; the audit gap shows in the logs.
  }
  return verdict;
}

export async function notifyLocationDenied(env: Env, userId: string): Promise<void> {
  await notifySecurity(env, userId, { kind: "security_location", title: "허용되지 않은 위치에서 로그인이 시도되었습니다", body: "로그인 활동을 확인하세요.", link: "/activity" });
}

/** The passkey proof succeeded; revoke its newly issued session if location denies it. */
export async function enforceLocationAfterPasskeyLogin(env: Env, request: Request, response: Response, userId: string, path: string): Promise<Response | null> {
  const place = await locationGate(env, { request, userId, path });
  if (place.allowed) return null;
  const issued = await findNewSessionFromResponse(env, response).catch(() => null);
  if (issued) await env.DB.prepare('DELETE FROM "session" WHERE token = ?').bind(issued.token).run().catch(() => null);
  await notifyLocationDenied(env, userId);
  return Response.json({ error: "Sign-in is not allowed from this location", code: "location_denied" }, { status: 403 });
}
