import type { Env } from "../env";

export type FingerprintMode = "disabled" | "observe" | "enforce";

export interface FingerprintEvent {
  eventId: string;
  visitorId: string;
  confidence: number;
  timestamp: number;
  bot?: "bad" | "good" | "not_detected";
  suspectScore?: number;
  replayed: boolean;
  tampering: boolean;
  mitmAttack: boolean;
  locationSpoofing: boolean;
  countryCode: string | null;
  eventOrigin: string;
  networkAddress: string | null;
}

export interface VerifiedFingerprint {
  event: FingerprintEvent | null;
  error?: "missing_event" | "invalid_event" | "provider_unavailable" | "replayed_event";
}

export interface FingerprintRisk {
  action: "allow" | "step_up" | "deny";
  reasons: string[];
  visitorDigest: string | null;
  trustedDeviceId: string | null;
  countryCode: string | null;
  networkDigest: string | null;
}

const REGION_HOSTS: Record<NonNullable<Env["FINGERPRINT_REGION"]>, string> = {
  us: "api.fpjs.io",
  eu: "eu.api.fpjs.io",
  ap: "ap.api.fpjs.io",
};

export function fingerprintMode(env: Env): FingerprintMode {
  const mode = env.FINGERPRINT_MODE ?? "disabled";
  if (mode !== "disabled" && mode !== "observe" && mode !== "enforce") {
    throw new Error("FINGERPRINT_MODE must be disabled, observe, or enforce");
  }
  return mode;
}

export function validateFingerprintConfig(env: Env): void {
  const mode = fingerprintMode(env);
  const region = env.FINGERPRINT_REGION ?? "us";
  if (!Object.hasOwn(REGION_HOSTS, region)) {
    throw new Error("FINGERPRINT_REGION must be us, eu, or ap");
  }
  if (mode === "disabled") return;

  const rawConfidence = env.FINGERPRINT_MIN_CONFIDENCE ?? "0.7";
  const confidence = rawConfidence.trim() ? Number(rawConfidence) : Number.NaN;
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("FINGERPRINT_MIN_CONFIDENCE must be between 0 and 1");
  }
  if (env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD !== undefined && env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD !== "") {
    const threshold = env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD.trim()
      ? Number(env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD)
      : Number.NaN;
    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
      throw new Error("FINGERPRINT_SUSPECT_SCORE_THRESHOLD must be between 0 and 100");
    }
  }
  const rawMaxAge = env.FINGERPRINT_MAX_EVENT_AGE_SECONDS ?? "120";
  const maxAge = rawMaxAge.trim() ? Number(rawMaxAge) : Number.NaN;
  if (!Number.isInteger(maxAge) || maxAge < 30 || maxAge > 600) {
    throw new Error("FINGERPRINT_MAX_EVENT_AGE_SECONDS must be between 30 and 600");
  }
  for (const origin of (env.FINGERPRINT_ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean)) {
    const url = new URL(origin);
    if (
      url.origin !== origin.replace(/\/$/, "") ||
      (url.protocol !== "https:" && !(url.protocol === "http:" && url.hostname === "localhost")) ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      throw new Error("FINGERPRINT_ALLOWED_ORIGINS entries must be HTTPS origins");
    }
  }
}

export async function verifyFingerprintEvent(input: {
  env: Env;
  request: Request;
  eventId: string | null;
}): Promise<VerifiedFingerprint> {
  if (!input.eventId) return { event: null, error: "missing_event" };
  const mode = fingerprintMode(input.env);
  if (mode === "disabled") return { event: null, error: "invalid_event" };
  if (!input.env.FINGERPRINT_SERVER_API_KEY) {
    return { event: null, error: "provider_unavailable" };
  }
  if (input.eventId.length > 160 || /[\u0000-\u0020/\\?#]/.test(input.eventId)) {
    return { event: null, error: "invalid_event" };
  }

  const region = input.env.FINGERPRINT_REGION ?? "us";
  const host = REGION_HOSTS[region];
  if (!host) return { event: null, error: "invalid_event" };

  let response: Response;
  try {
    response = await fetch(
      `https://${host}/v4/events/${encodeURIComponent(input.eventId)}`,
      {
        headers: {
          Authorization: `Bearer ${input.env.FINGERPRINT_SERVER_API_KEY}`,
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(3000),
      },
    );
  } catch {
    return { event: null, error: "provider_unavailable" };
  }
  if (!response.ok) {
    return {
      event: null,
      error: response.status >= 500 || response.status === 429
        ? "provider_unavailable"
        : "invalid_event",
    };
  }

  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    return { event: null, error: "invalid_event" };
  }
  const parsed = parseEvent(raw);
  if (!parsed || parsed.eventId !== input.eventId) {
    return { event: null, error: "invalid_event" };
  }

  const now = Date.now();
  const maxAge = Number(input.env.FINGERPRINT_MAX_EVENT_AGE_SECONDS ?? "120") * 1000;
  if (parsed.timestamp > now + 30_000 || now - parsed.timestamp > maxAge) {
    return { event: null, error: "invalid_event" };
  }

  const allowedOrigins = new Set([
    ...getAuthOrigins(input.env),
    ...(input.env.FINGERPRINT_ALLOWED_ORIGINS ?? "")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean)
      .flatMap((origin) => {
        try {
          return [new URL(origin).origin];
        } catch {
          return [];
        }
      }),
  ]);
  if (!allowedOrigins.has(parsed.eventOrigin)) {
    return { event: null, error: "invalid_event" };
  }
  const requestOrigin = input.request.headers.get("origin");
  if (requestOrigin) {
    try {
      const normalizedRequestOrigin = new URL(requestOrigin).origin;
      if (
        !allowedOrigins.has(normalizedRequestOrigin) ||
        normalizedRequestOrigin !== parsed.eventOrigin
      ) {
        return { event: null, error: "invalid_event" };
      }
    } catch {
      return { event: null, error: "invalid_event" };
    }
  }

  if (parsed.replayed) return { event: null, error: "replayed_event" };
  return { event: parsed };
}

function getAuthOrigins(env: Env): string[] {
  try {
    return [new URL(env.AUTH_BASE_URL).origin];
  } catch {
    return [];
  }
}

export async function consumeFingerprintLookupBudget(input: {
  env: Env;
  request: Request;
  limit?: number;
}): Promise<boolean> {
  const clientAddress = input.request.headers.get("cf-connecting-ip") ?? "local";
  const budgetKey = await digestVisitorId(input.env, `fingerprint-lookup:${clientAddress}`);
  const window = Math.floor(Date.now() / 60_000);
  const result = await input.env.DB.prepare(
    `INSERT INTO fingerprint_lookup_limits (budget_key, window_start, request_count)
     VALUES (?, ?, 1)
     ON CONFLICT(budget_key) DO UPDATE SET
       request_count = CASE
         WHEN fingerprint_lookup_limits.window_start = excluded.window_start
         THEN fingerprint_lookup_limits.request_count + 1
         ELSE 1
       END,
       window_start = excluded.window_start
     RETURNING request_count`,
  )
    .bind(budgetKey, window)
    .first<{ request_count: number }>();
  return (result?.request_count ?? Number.POSITIVE_INFINITY) <= (input.limit ?? 10);
}

export async function claimAndConsumeFingerprintEvent(input: {
  env: Env;
  eventId: string;
  userId?: string | null;
  context: string;
}): Promise<boolean> {
  const now = new Date();
  const claimedAt = now.toISOString();
  const claimToken = crypto.randomUUID();
  const results = await input.env.DB.batch([
    input.env.DB.prepare(
      "DELETE FROM fingerprint_event_claims WHERE expires_at < ?",
    ).bind(claimedAt),
    input.env.DB.prepare(
      `INSERT OR IGNORE INTO fingerprint_event_claims
        (event_id, user_id, context, claimed_at, expires_at, consumed_at, claim_token)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      input.eventId,
      input.userId ?? null,
      input.context,
      claimedAt,
      new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
      claimedAt,
      claimToken,
    ),
  ]);
  return results[1]?.meta.changes === 1;
}

export async function digestVisitorId(env: Env, visitorId: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.AUTH_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(visitorId)),
  );
  return Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function evaluateFingerprintRisk(input: {
  env: Env;
  userId: string;
  event: FingerprintEvent;
}): Promise<FingerprintRisk> {
  const visitorDigest = await digestVisitorId(input.env, input.event.visitorId);
  const now = new Date();
  const minimumConfidence = Number(input.env.FINGERPRINT_MIN_CONFIDENCE ?? "0.7");
  const reasons: string[] = [];
  let action: FingerprintRisk["action"] = "allow";

  if (input.event.bot === "bad") reasons.push("bot_detected");
  if (input.event.tampering) reasons.push("tampering_detected");
  if (input.event.mitmAttack) reasons.push("mitm_attack_detected");
  if (input.event.locationSpoofing) reasons.push("location_spoofing_detected");
  const suspectThreshold = input.env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD
    ? Number(input.env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD)
    : null;
  if (
    suspectThreshold !== null &&
    input.event.suspectScore !== undefined &&
    input.event.suspectScore >= suspectThreshold
  ) {
    reasons.push("suspect_score_threshold");
  }

  const trustedDevice = await input.env.DB.prepare(
    `SELECT id FROM trusted_devices
     WHERE user_id = ? AND visitor_digest = ? AND revoked_at IS NULL AND expires_at > ?
     LIMIT 1`,
  )
    .bind(input.userId, visitorDigest, now.toISOString())
    .first<{ id: string }>();

  if (input.event.confidence < minimumConfidence) {
    reasons.push("low_identification_confidence");
  } else if (!trustedDevice) {
    reasons.push("untrusted_device");
  }

  const previous = await input.env.DB.prepare(
    `SELECT visitor_digest, network_digest, country_code, occurred_at FROM auth_device_observations
     WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 1`,
  )
    .bind(input.userId)
    .first<{
      visitor_digest: string;
      network_digest: string | null;
      country_code: string | null;
      occurred_at: string;
    }>();

  const networkDigest = input.event.networkAddress
    ? await digestVisitorId(input.env, `network:${input.event.networkAddress}`)
    : null;

  if (previous) {
    const ageMs = now.getTime() - Date.parse(previous.occurred_at);
    const differentDevice = previous.visitor_digest !== visitorDigest;
    const differentNetwork = networkDigest !== null &&
      previous.network_digest !== null &&
      previous.network_digest !== networkDigest;
    if (
      ageMs >= 0 &&
      ageMs <= 30 * 60 * 1000 &&
      differentDevice &&
      previous.country_code &&
      input.event.countryCode &&
      previous.country_code !== input.event.countryCode
    ) {
      reasons.push("rapid_device_and_country_change");
    } else if (ageMs >= 0 && ageMs <= 15 * 60 * 1000 && differentNetwork) {
      reasons.push("rapid_network_change");
    } else if (ageMs >= 0 && ageMs <= 15 * 60 * 1000 && differentDevice) {
      reasons.push("rapid_device_change");
    }
  }

  const hardSignals = new Set([
    "bot_detected",
    "tampering_detected",
    "mitm_attack_detected",
    "location_spoofing_detected",
    "suspect_score_threshold",
    "rapid_device_and_country_change",
  ]);
  if (reasons.some((reason) => hardSignals.has(reason))) action = "deny";
  else if (
    reasons.includes("untrusted_device") ||
    reasons.includes("low_identification_confidence")
  ) {
    action = "step_up";
  }

  return {
    action,
    reasons,
    visitorDigest,
    trustedDeviceId: trustedDevice?.id ?? null,
    countryCode: input.event.countryCode,
    networkDigest,
  };
}

export async function recordFingerprintObservation(input: {
  env: Env;
  userId: string;
  event: FingerprintEvent;
  risk: FingerprintRisk;
}): Promise<void> {
  const now = new Date().toISOString();
  const keepSince = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  await input.env.DB.batch([
    input.env.DB.prepare("DELETE FROM auth_device_observations WHERE occurred_at < ?")
      .bind(keepSince),
    input.env.DB.prepare(
      `INSERT INTO auth_device_observations
        (id, user_id, visitor_digest, network_digest, country_code, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      crypto.randomUUID(),
      input.userId,
      input.risk.visitorDigest,
      input.risk.networkDigest,
      input.event.countryCode,
      now,
    ),
    ...(input.risk.trustedDeviceId
      ? [input.env.DB.prepare(
          "UPDATE trusted_devices SET last_seen_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
        ).bind(now, input.risk.trustedDeviceId, input.userId)]
      : []),
  ]);
}

function parseEvent(value: unknown): FingerprintEvent | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const identification = record.identification;
  if (!identification || typeof identification !== "object") return null;
  const identificationRecord = identification as Record<string, unknown>;
  const confidence = identificationRecord.confidence;
  if (!confidence || typeof confidence !== "object") return null;
  const confidenceScore = (confidence as Record<string, unknown>).score;
  const timestamp = record.timestamp;
  const eventUrl = record.url;
  const visitorId = identificationRecord.visitor_id;
  const eventId = record.event_id;
  if (
    typeof eventId !== "string" ||
    eventId.length === 0 ||
    typeof visitorId !== "string" ||
    visitorId.length === 0 ||
    typeof confidenceScore !== "number" ||
    !Number.isFinite(confidenceScore) ||
    confidenceScore < 0 ||
    confidenceScore > 1 ||
    typeof timestamp !== "number" ||
    !Number.isSafeInteger(timestamp) ||
    typeof eventUrl !== "string"
  ) {
    return null;
  }

  let eventOrigin: string;
  try {
    const parsedEventUrl = new URL(eventUrl);
    if (
      parsedEventUrl.protocol !== "https:" ||
      parsedEventUrl.username !== "" ||
      parsedEventUrl.password !== ""
    ) return null;
    eventOrigin = parsedEventUrl.origin;
  } catch {
    return null;
  }
  const ipInfo = record.ip_info;
  let countryCode: string | null = null;
  if (ipInfo && typeof ipInfo === "object") {
    const ipRecord = ipInfo as Record<string, unknown>;
    for (const version of ["v4", "v6"]) {
      const network = ipRecord[version];
      if (!network || typeof network !== "object") continue;
      const geolocation = (network as Record<string, unknown>).geolocation;
      if (!geolocation || typeof geolocation !== "object") continue;
      const code = (geolocation as Record<string, unknown>).country_code;
      if (typeof code === "string" && /^[A-Z]{2}$/.test(code)) {
        countryCode = code;
        break;
      }
    }
  }
  const suspectScore = typeof record.suspect_score === "number"
    ? record.suspect_score
    : undefined;
  if (
    record.suspect_score !== undefined &&
    (suspectScore === undefined || !Number.isFinite(suspectScore) || suspectScore < 0 || suspectScore > 100)
  ) {
    return null;
  }
  const ipAddress = typeof record.ip_address === "string" ? record.ip_address : null;

  const bot = record.bot;
  if (bot !== undefined && bot !== "bad" && bot !== "good" && bot !== "not_detected") {
    return null;
  }
  for (const flag of ["replayed", "tampering", "mitm_attack", "location_spoofing"] as const) {
    if (record[flag] !== undefined && typeof record[flag] !== "boolean") return null;
  }

  return {
    eventId,
    visitorId,
    confidence: confidenceScore,
    timestamp,
    bot,
    suspectScore,
    replayed: record.replayed === true,
    tampering: record.tampering === true,
    mitmAttack: record.mitm_attack === true,
    locationSpoofing: record.location_spoofing === true,
    countryCode,
    eventOrigin,
    networkAddress: ipAddress,
  };
}
