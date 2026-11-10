/**
 * The GeoIP policy family (docs/design/authentik-policies.md): static
 * country/ASN allow matching plus distance and impossible-travel checks
 * against recent login observations. Reuses the device-risk pipeline's geo
 * engine (src/security/geo.ts / evaluateGeoIpHistory) and its observation
 * storage; when geo data is unavailable the evaluation throws an error, and
 * the binding's failure result decides the outcome.
 */

import type { Env } from "../env";
import { evaluateGeoIpHistory } from "../security/fingerprint";
import { resolveGeoPoint } from "../security/geo";
import type { PolicyEvaluationContext, PolicyUserSnapshot } from "../policies/types";

export interface GeoIpPolicyConfig {
  /** Two-letter country codes; any match makes the static part pass. */
  countries: string[];
  /** Autonomous system numbers; any match makes the static part pass. */
  asns: number[];
  maxDistanceKm: number | null;
  distanceToleranceKm: number;
  historyLoginCount: number;
  checkImpossibleTravel: boolean;
  impossibleTravelToleranceKm: number;
}

export function validateGeoIpConfig(config: unknown): GeoIpPolicyConfig {
  const value = (config ?? {}) as Record<string, unknown>;
  const countries = Array.isArray(value.countries)
    ? value.countries.filter((entry): entry is string => typeof entry === "string" && /^[A-Za-z]{2}$/.test(entry)).map((entry) => entry.toUpperCase())
    : [];
  const asns = Array.isArray(value.asns)
    ? value.asns.filter((entry): entry is number => typeof entry === "number" && Number.isInteger(entry) && entry > 0)
    : [];
  const optionalNumber = (key: string, min: number, max: number): number | null => {
    const raw = value[key];
    if (raw === undefined || raw === null) return null;
    if (typeof raw !== "number" || !Number.isFinite(raw) || raw < min || raw > max) {
      throw new Error(`${key} must be a number between ${min} and ${max}`);
    }
    return raw;
  };
  const maxDistanceKm = optionalNumber("maxDistanceKm", 1, 20_000);
  const distanceToleranceKm = optionalNumber("distanceToleranceKm", 0, 5_000) ?? 0;
  const historyLoginCount = optionalNumber("historyLoginCount", 1, 50) ?? 3;
  const checkImpossibleTravel = value.checkImpossibleTravel === true;
  const impossibleTravelToleranceKm = optionalNumber("impossibleTravelToleranceKm", 0, 5_000) ?? 0;
  if (countries.length === 0 && asns.length === 0 && maxDistanceKm === null && !checkImpossibleTravel) {
    throw new Error("geoip policy requires countries, asns, a distance rule or an impossible-travel rule");
  }
  return {
    countries, asns, maxDistanceKm, distanceToleranceKm,
    historyLoginCount, checkImpossibleTravel, impossibleTravelToleranceKm,
  };
}

function staticPass(config: GeoIpPolicyConfig, geo: NonNullable<PolicyEvaluationContext["geo"]>): boolean | null {
  // An empty configured set passes; any configured country/ASN match makes the
  // static part pass ("If either country or ASN matching is configured, the
  // static part of the policy passes when any configured country or ASN match
  // succeeds").
  if (config.countries.length > 0 && geo.country !== undefined && geo.country !== null
      && config.countries.includes(String(geo.country).toUpperCase())) {
    return true;
  }
  if (config.asns.length > 0 && geo.asn !== undefined && config.asns.includes(geo.asn)) {
    return true;
  }
  if (config.countries.length === 0 && config.asns.length === 0) return null;
  return false;
}

export async function evaluateGeoIp(
  env: Env,
  config: GeoIpPolicyConfig,
  context: PolicyEvalationContextForGeo,
  user: PolicyUserSnapshot | null,
): Promise<{ passing: boolean; messages: string[] }> {
  const geo = context.geo;
  if (!geo || (geo.country === undefined && geo.asn === undefined && geo.lat === undefined)) {
    throw new Error("geoip data is unavailable for this login");
  }
  const outcome = staticPass(config, geo);
  if (outcome !== null) {
    return outcome
      ? { passing: true, messages: [] }
      : { passing: false, messages: [`the login country/ASN does not match the configured allowlist`] };
  }

  // Distance and impossible-travel checks compare the current login against
  // the user's recent observed logins (same storage the device-risk pipeline
  // uses), when those observations carry coordinates.
  if (config.maxDistanceKm === null && !config.checkImpossibleTravel) {
    return { passing: true, messages: [] };
  }
  if (!user) {
    throw new Error("geoip distance checks require a user");
  }
  const current = resolveGeoPoint({
    latitude: typeof geo.lat === "number" ? geo.lat : null,
    longitude: typeof geo.long === "number" ? geo.long : null,
    countryCode: typeof geo.country === "string" ? geo.country : null,
  });
  if (!current) {
    throw new Error("geoip coordinates are unavailable for this login");
  }
  const rows = await env.DB.prepare(
    `SELECT occurred_at AS occurredAt, latitude, longitude, geo_source AS geoSource
     FROM auth_device_observations
     WHERE user_id = ? AND latitude IS NOT NULL AND longitude IS NOT NULL
     ORDER BY occurred_at DESC LIMIT ?`,
  ).bind(user.id, Math.min(Math.max(config.historyLoginCount, 1), 50)).all<{
    occurredAt: string; latitude: number; longitude: number; geoSource: string;
  }>();
  const history = rows.results
    .filter((row) => Number.isFinite(row.latitude) && Number.isFinite(row.longitude))
    .map((row) => ({
      point: { latitude: row.latitude, longitude: row.longitude, source: row.geoSource === "event" ? "event" as const : "country" as const },
      occurredAt: Date.parse(row.occurredAt),
    }));
  const finding = evaluateGeoIpHistory({
    policy: {
      checkHistoryDistance: config.maxDistanceKm !== null,
      historyMaxDistanceKm: config.maxDistanceKm ?? 0,
      distanceToleranceKm: config.distanceToleranceKm,
      historyLoginCount: config.historyLoginCount,
      checkImpossibleTravel: config.checkImpossibleTravel,
      impossibleToleranceKm: config.impossibleTravelToleranceKm,
    },
    current: { latitude: current.latitude, longitude: current.longitude, source: current.source },
    history,
    now: Date.now(),
  });
  if (finding.reasons.length > 0) {
    return { passing: false, messages: [finding.reasons.join(", ")] };
  }
  return { passing: true, messages: [] };
}

type PolicyEvalationContextForGeo = PolicyEvaluationContext;
