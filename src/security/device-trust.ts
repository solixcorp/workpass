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

/**
 * Turn the verdict recorded at sign-in into a coarse grade. An allowed sign-in
 * starts high and loses a little for each soft reason that did not block it;
 * step-up and deny verdicts cap the grade.
 */
/** Private mode and open developer tools are recorded but do not lower the grade. */
const INFORMATIONAL = new Set(["incognito_detected", "developer_tools_detected"]);

export function gradeDeviceTrust(
  action: string | null,
  reasons: string[],
  signals?: Record<string, unknown> | null,
): { level: DeviceTrustLevel; score: number } {
  if (!action) return { level: "unknown", score: 0 };
  const counted = reasons.filter((reason) => !INFORMATIONAL.has(reason));
  if (action === "deny" || counted.some((reason) => HARD_REASONS.has(reason))) {
    return { level: "risky", score: Math.max(5, 25 - counted.length * 5) };
  }
  // The provider's own suspect score nudges the grade: a low score costs nothing.
  const suspect = typeof signals?.suspectScore === "number" ? signals.suspectScore : 0;
  const suspectPenalty = Math.min(10, Math.floor(Math.max(0, suspect) / 10));
  if (action === "step_up") return { level: "review", score: Math.max(30, 60 - counted.length * 5 - suspectPenalty) };
  const score = Math.max(70, 95 - counted.length * 5 - suspectPenalty);
  return { level: score >= 85 ? "trusted" : "normal", score };
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
