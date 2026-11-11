import { insertAuditEvent } from "../audit/store";
import type { Env } from "../env";
import { evaluateLocation, type LocationVerdict } from "./location-policy";

/**
 * Check a sign-in against the place policy and leave an audit event when it
 * does not pass: `authentication.location.denied` when the policy enforces,
 * `authentication.location.observe` when it only watches. Never throws; if
 * the check cannot be made while the policy enforces, the sign-in is refused.
 */
export async function locationGate(
  env: Env,
  input: { request: Request; userId: string | null; path: string },
): Promise<LocationVerdict> {
  let verdict: LocationVerdict;
  try {
    verdict = await evaluateLocation(env, { request: input.request, userId: input.userId });
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
      event_context: { reason: verdict.reason, nearestPlace: verdict.placeName, distanceM: verdict.distanceM },
    });
  } catch {
    // The decision stands; the audit gap shows in the logs.
  }
  return verdict;
}
