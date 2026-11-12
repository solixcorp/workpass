import type { Env } from "../env";

export type DeviceTrustLevel = "trusted" | "normal" | "review" | "risky" | "unknown";

export interface DeviceTrust {
  level: DeviceTrustLevel;
  /** 0-100, higher is safer. A rough guide for the owner, not a decision input. */
  score: number;
  observedAt: string | null;
}

export interface DeviceObservation extends DeviceTrust {
  action: string | null;
  reasons: string[];
  signals: Record<string, unknown> | null;
}

const HARD_REASONS = new Set([
  "bot_detected",
  "tampering_detected",
  "tor_network_detected",
  "ip_blocklisted",
  "virtual_machine_detected",
  "suspect_score_threshold",
  "rapid_device_and_country_change",
]);

/** Private mode and open developer tools are recorded but do not lower the grade. */
const INFORMATIONAL = new Set(["incognito_detected", "developer_tools_detected"]);

/**
 * Grade the device recorded at sign-in.
 *
 * The score is Fingerprint Pro's own Suspect Score turned around: 100 minus
 * the provider's 0-100 suspicion, so a device the provider considers clean
 * reads high. Observations recorded without a Suspect Score fall back to a
 * count of the reasons that were raised. The level still follows the verdict
 * (deny or a hard signal is risky, step-up is review), so a hard signal can
 * make a device risky even when the provider's score is low.
 */
export function gradeDeviceTrust(
  action: string | null,
  reasons: string[],
  signals?: Record<string, unknown> | null,
): { level: DeviceTrustLevel; score: number } {
  if (!action) return { level: "unknown", score: 0 };
  const counted = reasons.filter((reason) => !INFORMATIONAL.has(reason));
  const suspect = typeof signals?.suspectScore === "number" && Number.isFinite(signals.suspectScore)
    ? Math.min(100, Math.max(0, signals.suspectScore))
    : null;
  const fallback = (base: number, floor: number) => Math.max(floor, base - counted.length * 5);

  if (action === "deny" || counted.some((reason) => HARD_REASONS.has(reason))) {
    return { level: "risky", score: suspect !== null ? Math.round(100 - suspect) : fallback(25, 5) };
  }
  if (action === "step_up") {
    return { level: "review", score: suspect !== null ? Math.round(100 - suspect) : fallback(60, 30) };
  }
  const score = suspect !== null ? Math.round(100 - suspect) : fallback(95, 70);
  return { level: score >= 85 ? "trusted" : score >= 50 ? "normal" : "review", score };
}

interface ObservationRow {
  visitor_digest: string;
  occurred_at: string;
  risk_action: string | null;
  risk_reasons: string | null;
  signals: string | null;
}

function parseJson<T>(value: string | null, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

/** Latest recorded observation per device digest for one user. */
export async function latestObservations(env: Env, userId: string, digests: string[]): Promise<Map<string, DeviceObservation>> {
  const result = new Map<string, DeviceObservation>();
  const unique = [...new Set(digests.filter(Boolean))].slice(0, 50);
  if (unique.length === 0) return result;
  try {
    const placeholders = unique.map(() => "?").join(", ");
    const observations = await env.DB.prepare(
      `SELECT visitor_digest, occurred_at, risk_action, risk_reasons, signals
       FROM auth_device_observations
       WHERE user_id = ? AND visitor_digest IN (${placeholders})
       ORDER BY occurred_at DESC LIMIT 500`,
    ).bind(userId, ...unique).all<ObservationRow>();
    for (const row of observations.results) {
      if (result.has(row.visitor_digest)) continue;
      const reasons = parseJson<string[]>(row.risk_reasons, []);
      const signals = parseJson<Record<string, unknown> | null>(row.signals, null);
      result.set(row.visitor_digest, {
        ...gradeDeviceTrust(row.risk_action, reasons, signals),
        observedAt: row.occurred_at,
        action: row.risk_action,
        reasons,
        signals,
      });
    }
  } catch {
    // Observations are advisory; a missing table must not break the device list.
  }
  return result;
}
