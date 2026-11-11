/**
 * Where a sign-in may come from: named places (a centre and a radius) and a
 * policy that says how a sign-in is checked against them.
 *
 * Two signals exist and they differ in what they can be trusted for:
 * - the network position the Cloudflare edge derives from the client address:
 *   the visitor cannot set it, but it is coarse (a city, often tens of
 *   kilometres) and a VPN moves it;
 * - the position the browser reports after the person allows it: precise, but
 *   it comes from the person's own device and can be faked.
 * The policy is a way to reduce risk, not proof of where someone is.
 */

import type { Env } from "../env";
import { haversineKm } from "./geo";

export type LocationMode = "off" | "observe" | "enforce";
export type LocationSignal = "network" | "browser" | "network_or_browser";

export interface LocationPolicy {
  mode: LocationMode;
  signal: LocationSignal;
  /** Allowance added to a place's radius for the network position, which is coarse. */
  networkMarginKm: number;
  /** A browser position less precise than this is not accepted. */
  maxAccuracyM: number;
  exemptGroups: string[];
}

export const DEFAULT_LOCATION_POLICY: LocationPolicy = {
  mode: "off",
  signal: "network_or_browser",
  networkMarginKm: 30,
  maxAccuracyM: 1000,
  exemptGroups: [],
};

export interface Place {
  id: string;
  name: string;
  latitude: number;
  longitude: number;
  radiusM: number;
  enabled: boolean;
}

export const PROOF_COOKIE = "wp_location";
export const PROOF_TTL_SECONDS = 15 * 60;

const MODES = new Set(["off", "observe", "enforce"]);
const SIGNALS = new Set(["network", "browser", "network_or_browser"]);

export async function loadLocationPolicy(env: Env): Promise<LocationPolicy> {
  try {
    const row = await env.DB.prepare(
      "SELECT mode, signal, network_margin_km AS networkMarginKm, max_accuracy_m AS maxAccuracyM, exempt_groups AS exemptGroups FROM location_policy WHERE id = 1",
    ).first<{ mode: string; signal: string; networkMarginKm: number; maxAccuracyM: number; exemptGroups: string }>();
    if (!row || !MODES.has(row.mode) || !SIGNALS.has(row.signal)) return DEFAULT_LOCATION_POLICY;
    let exempt: string[] = [];
    try {
      const parsed: unknown = JSON.parse(row.exemptGroups);
      if (Array.isArray(parsed)) exempt = parsed.filter((id): id is string => typeof id === "string");
    } catch { /* unreadable: no exemptions */ }
    return { mode: row.mode as LocationMode, signal: row.signal as LocationSignal, networkMarginKm: row.networkMarginKm, maxAccuracyM: row.maxAccuracyM, exemptGroups: exempt };
  } catch {
    // Not migrated yet: the policy is off.
    return DEFAULT_LOCATION_POLICY;
  }
}

export async function saveLocationPolicy(env: Env, policy: LocationPolicy, adminId: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO location_policy (id, mode, signal, network_margin_km, max_accuracy_m, exempt_groups, updated_by, updated_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (id) DO UPDATE SET mode = excluded.mode, signal = excluded.signal, network_margin_km = excluded.network_margin_km,
       max_accuracy_m = excluded.max_accuracy_m, exempt_groups = excluded.exempt_groups, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
  ).bind(policy.mode, policy.signal, policy.networkMarginKm, policy.maxAccuracyM, JSON.stringify(policy.exemptGroups), adminId, new Date().toISOString()).run();
}

export async function listPlaces(env: Env, onlyEnabled = false): Promise<Place[]> {
  try {
    const rows = await env.DB.prepare(
      `SELECT id, name, latitude, longitude, radius_m AS radiusM, enabled FROM location_places ${onlyEnabled ? "WHERE enabled = 1" : ""} ORDER BY name ASC LIMIT 200`,
    ).all<{ id: string; name: string; latitude: number; longitude: number; radiusM: number; enabled: number }>();
    return rows.results.map((row) => ({ ...row, enabled: row.enabled === 1 }));
  } catch {
    return [];
  }
}

/** The position the edge derived for this request, when it provides one. */
export function networkPoint(request: Request): { latitude: number; longitude: number; country: string | null; city: string | null } | null {
  const cf = (request as unknown as { cf?: { latitude?: unknown; longitude?: unknown; country?: unknown; city?: unknown } }).cf;
  const latitude = Number(cf?.latitude);
  const longitude = Number(cf?.longitude);
  if (!cf || cf.latitude === undefined || cf.longitude === undefined || !Number.isFinite(latitude) || !Number.isFinite(longitude)) return null;
  return { latitude, longitude, country: typeof cf.country === "string" ? cf.country : null, city: typeof cf.city === "string" ? cf.city : null };
}

export function nearestPlace(point: { latitude: number; longitude: number }, places: Place[]): { place: Place; distanceM: number } | null {
  let best: { place: Place; distanceM: number } | null = null;
  for (const place of places) {
    const distanceM = haversineKm({ ...point, source: "event" }, { latitude: place.latitude, longitude: place.longitude, source: "event" }) * 1000;
    if (!best || distanceM - place.radiusM < best.distanceM - best.place.radiusM) best = { place, distanceM };
  }
  return best;
}

export interface LocationVerdict {
  /** The sign-in may go on (always true unless the policy enforces and the check failed). */
  allowed: boolean;
  /** The check itself passed, whatever the mode. */
  pass: boolean;
  mode: LocationMode;
  method: "off" | "exempt" | "network" | "browser" | "none";
  /** The browser could still satisfy the check by sharing its position. */
  needsBrowser: boolean;
  reason: "ok" | "outside" | "no_signal" | "needs_browser" | "no_places";
  placeName: string | null;
  distanceM: number | null;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function proofTokenFromRequest(request: Request): string | null {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === PROOF_COOKIE) {
      const value = rest.join("=");
      return /^[A-Za-z0-9_-]{20,100}$/.test(value) ? value : null;
    }
  }
  return null;
}

async function validProof(env: Env, token: string): Promise<{ placeId: string; placeName: string; distanceM: number } | null> {
  const row = await env.DB.prepare(
    `SELECT p.distance_m AS distanceM, l.name AS name, l.id AS placeId FROM location_proofs p
     JOIN location_places l ON l.id = p.place_id AND l.enabled = 1
     WHERE p.token_hash = ? AND p.expires_at > ?`,
  ).bind(await sha256Hex(token), new Date().toISOString()).first<{ distanceM: number; name: string; placeId: string }>().catch(() => null);
  return row ? { placeId: row.placeId, placeName: row.name, distanceM: row.distanceM } : null;
}

export function parsePlaceIds(value: string): string[] {
  try { const ids: unknown = JSON.parse(value); return Array.isArray(ids) ? ids.filter((id): id is string => typeof id === "string") : []; } catch { return []; }
}

async function exempt(env: Env, policy: LocationPolicy, userId: string): Promise<boolean> {
  if (policy.exemptGroups.length === 0) return false;
  const row = await env.DB.prepare(
    `SELECT 1 AS n FROM directory_group_members WHERE user_id = ? AND group_id IN (${policy.exemptGroups.map(() => "?").join(",")}) LIMIT 1`,
  ).bind(userId, ...policy.exemptGroups).first().catch(() => null);
  return row !== null;
}

/** Check a request against the policy. `policy` overrides the stored one (to test a change before saving it). */
export async function evaluateLocation(
  env: Env,
  input: { request: Request; userId: string | null; policy?: LocationPolicy; subject?: string; groupOverride?: { groupId: string; placeIds: string[] } },
): Promise<LocationVerdict> {
  let policy = input.policy ?? await loadLocationPolicy(env);
  let scopedIds: string[] | null = null;
  if (input.subject) {
    const rule = await env.DB.prepare("SELECT place_ids, mode FROM location_app_rules WHERE subject = ?").bind(input.subject).first<{ place_ids: string; mode: "observe" | "enforce" }>();
    if (!rule) return { allowed: true, pass: true, mode: "off", method: "off", needsBrowser: false, reason: "ok", placeName: null, distanceM: null };
    policy = { ...policy, mode: rule.mode };
    scopedIds = parsePlaceIds(rule.place_ids);
  }
  const result = (pass: boolean, rest: Partial<LocationVerdict>): LocationVerdict => ({
    allowed: pass || policy.mode !== "enforce", pass, mode: policy.mode, method: "none", needsBrowser: false,
    reason: pass ? "ok" : "outside", placeName: null, distanceM: null, ...rest,
  });
  if (policy.mode === "off") return result(true, { method: "off" });
  if (input.userId && await exempt(env, policy, input.userId)) return result(true, { method: "exempt" });
  if (!input.subject && input.userId) {
    const rows = await env.DB.prepare("SELECT r.group_id, r.place_ids FROM location_group_rules r JOIN directory_group_members m ON m.group_id = r.group_id WHERE m.user_id = ?").bind(input.userId).all<{ group_id: string; place_ids: string }>();
    const rules = rows.results.filter((row) => row.group_id !== input.groupOverride?.groupId).map((row) => parsePlaceIds(row.place_ids));
    if (input.groupOverride) {
      const member = await env.DB.prepare("SELECT 1 FROM directory_group_members WHERE group_id = ? AND user_id = ?").bind(input.groupOverride.groupId, input.userId).first();
      if (member && input.groupOverride.placeIds.length) rules.push(input.groupOverride.placeIds);
    }
    if (rules.length) scopedIds = [...new Set(rules.flat())];
  }
  const places = (await listPlaces(env, true)).filter((place) => scopedIds === null || scopedIds.includes(place.id));
  if (places.length === 0) return result(scopedIds === null, { reason: "no_places" });

  const point = policy.signal === "browser" ? null : networkPoint(input.request);
  let nearest: { place: Place; distanceM: number } | null = null;
  if (point) {
    nearest = nearestPlace(point, places);
    if (nearest && nearest.distanceM <= nearest.place.radiusM + policy.networkMarginKm * 1000) {
      return result(true, { method: "network", placeName: nearest.place.name, distanceM: Math.round(nearest.distanceM) });
    }
  }
  if (policy.signal !== "network") {
    const token = proofTokenFromRequest(input.request);
    const proof = token ? await validProof(env, token) : null;
    if (proof && places.some((place) => place.id === proof.placeId)) return result(true, { method: "browser", placeName: proof.placeName, distanceM: proof.distanceM });
  }
  const needsBrowser = policy.signal !== "network";
  return result(false, {
    needsBrowser,
    reason: point ? "outside" : policy.signal === "network" ? "no_signal" : "needs_browser",
    placeName: nearest?.place.name ?? null,
    distanceM: nearest ? Math.round(nearest.distanceM) : null,
  });
}

/**
 * Check a position the browser reported against the places and, when it is
 * inside one, remember that for a few minutes under a random token that the
 * caller sets as a cookie. The position itself is not stored.
 */
export async function recordLocationProof(
  env: Env,
  input: { request: Request; latitude: number; longitude: number; accuracyM: number },
): Promise<{ ok: true; token: string } | { ok: false; reason: "outside" | "inaccurate" | "rate_limited" | "unavailable" }> {
  const policy = await loadLocationPolicy(env);
  if (policy.signal === "network") return { ok: false, reason: "unavailable" };
  const places = await listPlaces(env, true);
  const ip = (input.request.headers.get("cf-connecting-ip") ?? "local").slice(0, 64);
  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM location_proofs WHERE client_ip = ? AND created_at > ?")
    .bind(ip, new Date(Date.now() - 10 * 60_000).toISOString()).first<{ n: number }>().catch(() => null);
  if ((recent?.n ?? 0) >= 30) return { ok: false, reason: "rate_limited" };
  if (input.accuracyM > policy.maxAccuracyM) return { ok: false, reason: "inaccurate" };
  const nearest = nearestPlace(input, places);
  if (!nearest || nearest.distanceM > nearest.place.radiusM) return { ok: false, reason: "outside" };
  const token = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO location_proofs (token_hash, place_id, distance_m, accuracy_m, client_ip, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).bind(await sha256Hex(token), nearest.place.id, Math.round(nearest.distanceM), Math.round(input.accuracyM), ip, new Date(now).toISOString(), new Date(now + PROOF_TTL_SECONDS * 1000).toISOString()).run();
  return { ok: true, token };
}

export function proofCookie(env: Env, token: string): string {
  const secure = env.AUTH_BASE_URL.startsWith("https://") ? "; Secure" : "";
  return `${PROOF_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${PROOF_TTL_SECONDS}${secure}`;
}
