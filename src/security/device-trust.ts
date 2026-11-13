import type { Env } from "../env";

export type DeviceTrustLevel = "trusted" | "normal" | "review" | "risky" | "unknown";

export interface DeviceTrust {
  level: DeviceTrustLevel;
  /** 0-100, higher is safer. A rough guide for the owner, not a decision input. */
  score: number | null;
  observedAt: string | null;
  reasons: DeviceTrustReason[];
}

export interface DeviceObservation extends Omit<DeviceTrust, "reasons"> {
  action: string | null;
  reasons: string[];
  signals: Record<string, unknown> | null;
}

export interface DeviceTrustReason {
  code: string;
  label: string;
  severity: "info" | "warning" | "danger";
}

export const DEVICE_TRUST_BANDS = {
  risky: { min: 0, max: 29 },
  review: { min: 30, max: 59 },
  normal: { min: 60, max: 84 },
  trusted: { min: 85, max: 100 },
} as const;

const REASON_LABELS: Record<string, string> = {
  bot_detected: "자동화된 봇 감지", tampering_detected: "기기 정보 조작 감지",
  tor_network_detected: "Tor 네트워크 감지", ip_blocklisted: "차단 목록에 있는 IP 주소",
  virtual_machine_detected: "가상 머신 감지", suspect_score_threshold: "의심 신호가 기준을 초과함",
  rapid_device_and_country_change: "짧은 시간에 기기와 국가가 바뀜",
  incognito_detected: "시크릿 모드 사용", developer_tools_detected: "개발자 도구 사용",
  vpn_detected: "VPN 감지", proxy_detected: "프록시 감지", privacy_settings_detected: "개인정보 보호 설정 사용",
  rare_device_detected: "드문 기기 구성", high_activity_device_detected: "기기에서 비정상적으로 많은 활동",
  simulator_detected: "시뮬레이터 감지", datacenter_ip_detected: "데이터센터 네트워크 사용",
  low_identification_confidence: "기기 식별의 정확도가 낮음", untrusted_device: "아직 신뢰하지 않은 기기",
  rapid_network_change: "짧은 시간에 네트워크가 바뀜", rapid_device_change: "짧은 시간에 기기가 바뀜",
  geo_position_unavailable: "위치 정보를 확인할 수 없음", history_distance_exceeded: "이전 로그인 위치와 멀리 떨어짐",
  impossible_travel: "이동하기 어려운 거리에서 연속 로그인", new_device: "처음 보는 기기", new_country: "처음 보는 국가",
  provider_unavailable: "기기 확인 서비스에 연결할 수 없음",
};

export function deviceTrustReasons(reasons: string[]): DeviceTrustReason[] {
  return [...new Set(reasons)].map((code) => ({
    code, label: REASON_LABELS[code] ?? "추가 기기 확인 신호",
    severity: HARD_REASONS.has(code) || code === "impossible_travel" ? "danger"
      : INFORMATIONAL.has(code) ? "info" : "warning",
  }));
}

const HARD_REASONS = new Set([
  "bot_detected",
  "tampering_detected",
  "tor_network_detected",
  "ip_blocklisted",
  "virtual_machine_detected",
  "suspect_score_threshold",
  "rapid_device_and_country_change",
  "impossible_travel",
]);

/** Private mode and open developer tools are recorded but do not lower the grade. */
const INFORMATIONAL = new Set(["incognito_detected", "developer_tools_detected", "privacy_settings_detected", "geo_position_unavailable", "new_device", "new_country"]);

function levelForScore(score: number): DeviceTrustLevel {
  return score >= DEVICE_TRUST_BANDS.trusted.min ? "trusted"
    : score >= DEVICE_TRUST_BANDS.normal.min ? "normal"
    : score >= DEVICE_TRUST_BANDS.review.min ? "review"
    : "risky";
}

/**
 * Grade the device recorded at sign-in.
 *
 * When Fingerprint Pro's Suspect Score was recorded, the score is 100 minus
 * it, clamped to 0-100, and the level is the band that score falls in. Nothing
 * else moves either value; the verdict and reasons are shown beside them.
 * Observations recorded without a Suspect Score fall back to the verdict and a
 * count of the reasons raised.
 */
export function gradeDeviceTrust(
  action: string | null,
  reasons: string[],
  signals?: Record<string, unknown> | null,
): { level: DeviceTrustLevel; score: number | null } {
  if (!action) return { level: "unknown", score: null };
  if (typeof signals?.suspectScore === "number" && Number.isFinite(signals.suspectScore)) {
    const score = Math.round(100 - Math.min(100, Math.max(0, signals.suspectScore)));
    return { level: levelForScore(score), score };
  }
  const counted = reasons.filter((reason) => !INFORMATIONAL.has(reason));
  const fallback = (base: number, floor: number) => Math.max(floor, base - counted.length * 5);
  if (action === "deny" || counted.some((reason) => HARD_REASONS.has(reason))) {
    return { level: "risky", score: Math.min(DEVICE_TRUST_BANDS.risky.max, fallback(25, 5)) };
  }
  if (action === "step_up") {
    return { level: "review", score: Math.min(DEVICE_TRUST_BANDS.review.max, fallback(60, 30)) };
  }
  const score = fallback(95, 70);
  return { level: levelForScore(score), score };
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
