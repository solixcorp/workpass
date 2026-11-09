import type { Env } from "../env";
import type { AuthInstance } from "../auth/config";
import { digestVisitorId } from "./fingerprint";
import { insertAuditEvent } from "../audit/store";

/**
 * Session network/GeoIP binding — the session-side half of authentik's
 * GeoIP model (docs.goauthentik.io/security/security-hardening). Login-time
 * geo checks alone never catch a session cookie that is hijacked later; the
 * binding ties an issued session to the network/location it was created in
 * and terminates it (with a logout-style audit event) when it is used from
 * outside that envelope.
 *
 * Binding data comes from Cloudflare edge context (`request.cf`, derived from
 * the client IP by the edge, not from any client-supplied header):
 * - network digest: HMAC of the client IP (no raw IP is stored),
 * - ASN digest: HMAC of the autonomous-system number,
 * - country code, city digest (city equality only; the raw string is not stored).
 *
 * Strictness levels follow authentik's choices, adapted to available data:
 * - network: off / asn / asn_and_ip — the exact-IP tier is redundant here
 *   because our only network identity is the IP, so the two upper tiers differ
 *   from `asn_and_ip` only in authentik's own DB, which adds prefixes.
 * - geoip: off / country / country_and_city.
 *
 * Documented deviations from authentik:
 * - A missing binding row (session predating the feature, or binding data
 *   unavailable at creation) is allowed, not terminated: we cannot reconstruct
 *   the envelope retroactively and a blanket kill would log out everyone at
 *   rollout. New sessions always bind when data exists.
 * - Missing location data at enforcement time on a bound session is treated
 *   as a violation in `enforce` (authentik-parallel fail-closed behavior).
 */

export type SessionBindingMode = "disabled" | "observe" | "enforce";
export type NetworkBindingLevel = "off" | "asn" | "asn_and_ip";
export type GeoIpBindingLevel = "off" | "country" | "country_and_city";

export function sessionBindingMode(env: Env): SessionBindingMode {
  const mode = env.SESSION_BINDING_MODE ?? "disabled";
  if (mode !== "disabled" && mode !== "observe" && mode !== "enforce") {
    throw new Error("SESSION_BINDING_MODE must be disabled, observe, or enforce");
  }
  return mode;
}

export function networkBindingLevel(env: Env): NetworkBindingLevel {
  const level = env.SESSION_BINDING_NETWORK ?? "off";
  if (level !== "off" && level !== "asn" && level !== "asn_and_ip") {
    throw new Error("SESSION_BINDING_NETWORK must be off, asn, or asn_and_ip");
  }
  return level;
}

export function geoIpBindingLevel(env: Env): GeoIpBindingLevel {
  const level = env.SESSION_BINDING_GEOIP ?? "off";
  if (level !== "off" && level !== "country" && level !== "country_and_city") {
    throw new Error("SESSION_BINDING_GEOIP must be off, country, or country_and_city");
  }
  return level;
}

export function validateSessionBindingConfig(env: Env): void {
  sessionBindingMode(env);
  networkBindingLevel(env);
  geoIpBindingLevel(env);
}

/** Paths where a bound session is actively used on an interactive surface. */
const enforcedPaths = new Set(["/api/auth/get-session", "/api/auth/oauth2/authorize"]);

export function isSessionBindingEnforcedPath(path: string): boolean {
  return enforcedPaths.has(path);
}

interface BindingObservation {
  ip: string | null;
  asn: number | null;
  country: string | null;
  city: string | null;
}

/** Edge-derived client data; never client headers other than cf-connecting-ip. */
function observeClient(request: Request | null): BindingObservation {
  if (!request) {
    return { ip: null, asn: null, country: null, city: null };
  }
  const cf = (request as unknown as { cf?: unknown }).cf;
  let asn: number | null = null;
  let country: string | null = null;
  let city: string | null = null;
  if (cf && typeof cf === "object") {
    const cfRecord = cf as Record<string, unknown>;
    if (typeof cfRecord.asn === "number" && Number.isSafeInteger(cfRecord.asn)) {
      asn = cfRecord.asn;
    }
    if (typeof cfRecord.country === "string" && /^[A-Z]{2}$/.test(cfRecord.country)) {
      country = cfRecord.country;
    }
    if (typeof cfRecord.city === "string" && cfRecord.city.length > 0 && cfRecord.city.length <= 128) {
      city = cfRecord.city;
    }
  }
  return { ip: request.headers.get("cf-connecting-ip"), asn, country, city };
}

interface BindingRow {
  session_token: string;
  network_digest: string | null;
  asn_digest: string | null;
  country_code: string | null;
  city_digest: string | null;
  network_level: NetworkBindingLevel;
  geoip_level: GeoIpBindingLevel;
}

/**
 * Persist the network/geo envelope for a freshly created session. Best-effort
 * bookkeeping: a failure never blocks sign-in, and no binding row is written
 * when mode is disabled or edge data is unavailable (the session then runs
 * unbound until re-login in an environment with data).
 */
export async function bindSessionNetwork(input: {
  env: Env;
  sessionToken: string;
  userId: string;
  request: Request | null;
}): Promise<boolean> {
  const mode = sessionBindingMode(input.env);
  const networkLevel = networkBindingLevel(input.env);
  const geoIpLevel = geoIpBindingLevel(input.env);
  if (mode === "disabled" || (networkLevel === "off" && geoIpLevel === "off")) {
    return false;
  }
  if (
    !input.sessionToken ||
    typeof input.sessionToken !== "string" ||
    input.sessionToken.length === 0 ||
    input.sessionToken.length > 512
  ) {
    return false;
  }
  const client = observeClient(input.request);
  const hasNetworkData = client.ip !== null || client.asn !== null;
  const hasGeoData = client.country !== null;
  // Store an envelope only when the data for at least one configured level is
  // complete; a partial envelope would turn every later check into a violation.
  if (!(networkLevel !== "off" && hasNetworkData) && !(geoIpLevel !== "off" && hasGeoData)) {
    return false;
  }

  const row: BindingRow = {
    session_token: input.sessionToken,
    network_digest: await digestVisitorId(input.env, `network:${client.ip ?? ""}`),
    asn_digest: await digestVisitorId(input.env, `asn:${client.asn ?? ""}`),
    country_code: client.country,
    city_digest: await digestVisitorId(input.env, `city:${client.city ?? ""}`),
    network_level: networkLevel,
    geoip_level: geoIpLevel,
  };
  try {
    await input.env.DB.prepare(
      `INSERT INTO session_network_bindings
        (session_token, user_id, network_digest, asn_digest, country_code, city_digest, network_level, geoip_level, bound_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(session_token) DO NOTHING`,
    )
      .bind(
        row.session_token,
        input.userId,
        row.network_digest,
        row.asn_digest,
        row.country_code,
        row.city_digest,
        row.network_level,
        row.geoip_level,
        new Date().toISOString(),
      )
      .run();
    return true;
  } catch (error) {
    console.warn("Session network binding could not be recorded", {
      name: error instanceof Error ? error.name : "UnknownError",
    });
    return false;
  }
}

export type BindingVerdict =
  | { action: "allow" }
  | { action: "observe"; reason: "network_moved" | "location_moved" }
  | { action: "terminate"; reason: "network_moved" | "location_moved" };

export async function enforceSessionNetworkBinding(input: {
  request: Request;
  env: Env;
  sessionToken: string | null;
  userId: string | null;
  path: string;
}): Promise<Response | null> {
  const env = input.env;
  const mode = sessionBindingMode(env);
  if (mode === "disabled" || !isSessionBindingEnforcedPath(input.path)) return null;

  const verdict = await evaluateSessionBinding({
    env,
    request: input.request,
    sessionToken: input.sessionToken,
    userId: input.userId,
    mode,
  });
  if (verdict.action === "allow") return null;

  try {
    await insertAuditEvent(env, {
      id: crypto.randomUUID(),
      actor_user_id: input.userId,
      target_user_id: input.userId,
      event_type: mode === "enforce"
        ? "authentication.session.location_violation"
        : "authentication.session.location_drift.observe",
      outcome: "success",
      request_path: input.path,
    });
  } catch {
    // The verdict below applies even if this audit row cannot be written;
    // session termination itself is the durable protection.
  }
  if (verdict.action === "observe") return null;
  return Response.json(
    { error: "Session was terminated because the network or location changed" },
    { status: 401 },
  );
}

async function evaluateSessionBinding(input: {
  request: Request;
  env: Env;
  sessionToken: string | null;
  userId: string | null;
  mode: "observe" | "enforce";
}): Promise<BindingVerdict> {
  const env = input.env;
  if (!input.sessionToken || !input.userId) return { action: "allow" };

  const row = await env.DB.prepare(
    `SELECT session_token, network_digest, asn_digest, country_code, city_digest, network_level, geoip_level
     FROM session_network_bindings WHERE session_token = ? LIMIT 1`,
  )
    .bind(input.sessionToken)
    .first<BindingRow>();
  // Missing envelope: session predates the feature or was created without edge
  // data. Allowed (documented deviation); new sessions bind themselves.
  if (!row) return { action: "allow" };

  const client = observeClient(input.request);
  let movedNetwork: boolean | null = null;
  let movedLocation: boolean | null = null;

  if (row.network_level !== "off") {
    // A stored level with no captured data cannot be compared at all; skip
    // instead of terminating (the envelope was never complete for that level).
    if (row.asn_digest !== null && (row.network_level === "asn" || row.network_level === "asn_and_ip")) {
      movedNetwork = false;
      const asnDigest = await digestVisitorId(env, `asn:${client.asn ?? ""}`);
      if (!client.asn || row.asn_digest !== asnDigest) movedNetwork = true;
      if (row.network_level === "asn_and_ip" && row.network_digest !== null) {
        const networkDigest = await digestVisitorId(env, `network:${client.ip ?? ""}`);
        if (!client.ip || row.network_digest !== networkDigest) movedNetwork = true;
      }
    }
  }

  if (row.geoip_level !== "off" && row.country_code !== null) {
    movedLocation = false;
    if (!client.country) {
      // Location data is missing at enforcement time on a session that WAS
      // bound with location data: authentik treats lookup failure as a
      // binding violation, and so do we in enforce mode.
      movedLocation = true;
    } else {
      if (client.country !== row.country_code) movedLocation = true;
      // City granularity only when the edge reports a city for this request;
      // an unavailable city keeps the decision at country level.
      if (row.geoip_level === "country_and_city" && client.city) {
        const cityDigest = await digestVisitorId(env, `city:${client.city}`);
        if (row.city_digest !== cityDigest) movedLocation = true;
      }
    }
  }

  const networkViolation = movedNetwork === true;
  const locationViolation = movedLocation === true;
  if (!networkViolation && !locationViolation) return { action: "allow" };
  const reason = networkViolation ? "network_moved" : "location_moved";
  return input.mode === "enforce" ? { action: "terminate", reason } : { action: "observe", reason };
}

/** Remove envelope rows for ended sessions and old bindings. */
export async function cleanupSessionNetworkBindings(env: Env, now: Date): Promise<void> {
  const keepSince = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare("DELETE FROM session_network_bindings WHERE bound_at < ?")
    .bind(keepSince)
    .run();
}

/** Extract the Better Auth session token from request cookies. */
export function sessionTokenFromRequest(request: Request): string | null {
  const header = request.headers.get("cookie");  if (!header) return null;
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0) continue;
    const name = pair.slice(0, separator).trim();
    if (!name.endsWith("session_token")) continue;
    const rawValue = pair.slice(separator + 1).trim();
    let decodedValue: string;
    try {
      decodedValue = decodeURIComponent(rawValue);
    } catch {
      decodedValue = rawValue;
    }
    const token = decodedValue.split(".", 1)[0];
    if (token) return token;
  }
  return null;
}

/**
 * Resolve the acting session once and evaluate its network/location envelope.
 * Called from auditAuthRequest for every Better Auth request; unauthenticated
 * visitors and binding-evaluation failures never block the underlying flow.
 * Binding data is only checked on interactive identity surfaces (session
 * validation and OAuth authorization/consent), matching the codebase policy
 * of evaluating risk at identity boundaries rather than on every request.
 */
export async function enforceSessionGeoBinding(input: {
  request: Request;
  env: Env;
  auth: AuthInstance;
}): Promise<Response | null> {
  let path: string;
  try {
    path = new URL(input.request.url).pathname;
  } catch {
    return null;
  }
  let mode: SessionBindingMode;
  try {
    mode = sessionBindingMode(input.env);
  } catch {
    return null;
  }
  if (mode === "disabled" || !isSessionBindingEnforcedPath(path)) return null;
  try {
    const session = await input.auth.api.getSession({ headers: input.request.headers });
    if (!session) return null;
    return await enforceSessionNetworkBinding({
      request: input.request,
      env: input.env,
      sessionToken: sessionTokenFromRequest(input.request),
      userId: session.user.id,
      path,
    });
  } catch {
    // A binding evaluation failure must not become an availability failure.
    return null;
  }
}
