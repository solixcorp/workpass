import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { TestD1 } from "../helpers/test-d1";
import { haversineKm, resolveGeoPoint } from "../../src/security/geo";
import {
  digestVisitorId,
  evaluateFingerprintRisk,
  evaluateGeoIpHistory,
  geoIpHistoryPolicy,
  IMPOSSIBLE_TRAVEL_KM_PER_HOUR,
} from "../../src/security/fingerprint";
import { ensureApplicationTables } from "../../src/db/schema";

const SECRET = "impossible-travel-test-secret-0123456789abcdef";

function envWith(db: TestD1, extra: Record<string, string> = {}): Env {
  return {
    DB: db as unknown as Env["DB"],
    AUTH_SECRET: SECRET,
    AUTH_BASE_URL: "https://idp.test",
    FINGERPRINT_SERVER_API_KEY: "server-key-for-tests",
    ...extra,
  } as unknown as Env;
}

interface SeedRow {
  userId: string;
  visitorDigest: string;
  networkDigest?: string | null;
  countryCode?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  geoSource?: string | null;
  occurredAt: string;
}

async function seedObservation(db: TestD1, row: SeedRow): Promise<void> {
  await db.prepare(
    `INSERT INTO auth_device_observations
      (id, user_id, visitor_digest, network_digest, country_code, latitude, longitude, geo_source, occurred_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    crypto.randomUUID(),
    row.userId,
    row.visitorDigest,
    row.networkDigest ?? null,
    row.countryCode ?? null,
    row.latitude ?? null,
    row.longitude ?? null,
    row.geoSource ?? null,
    row.occurredAt,
  ).run();
}

function event(overrides: Record<string, unknown> = {}) {
  return {
    eventId: "evt_test",
    visitorId: "visitor-a",
    confidence: 0.9,
    timestamp: Date.now(),
    replayed: false,
    tampering: false,
    mitmAttack: false,
    locationSpoofing: false,
    countryCode: null,
    latitude: null,
    longitude: null,
    eventOrigin: "https://idp.test",
    networkAddress: "203.0.113.10",
    ...overrides,
  } as Parameters<typeof evaluateFingerprintRisk>[0]["event"];
}

function hoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

async function setup(): Promise<TestD1> {
  const db = new TestD1();
  await ensureApplicationTables({ DB: db as unknown as Env["DB"] } as unknown as Env);
  return db;
}

/** Seed visitor digests through the real HMAC so identity comparisons match. */
async function seedVisitors(env: Env, userId: string, visitors: string[]): Promise<Record<string, string>> {
  const digests: Record<string, string> = {};
  for (const visitor of visitors) {
    digests[visitor] = await digestVisitorId(env, visitor);
  }
  return digests;
}

describe("geo coordinates", () => {
  test("event coordinates win over country centroids", () => {
    const point = resolveGeoPoint({ latitude: 37.57, longitude: 126.98, countryCode: "US" });
    expect(point).toEqual({ latitude: 37.57, longitude: 126.98, source: "event" });
  });

  test("country centroids fall back, unknown countries resolve null", () => {
    const point = resolveGeoPoint({ latitude: null, longitude: null, countryCode: "KR" });
    expect(point?.source).toBe("country");
    expect(point?.latitude).toBeCloseTo(35.91);
    expect(resolveGeoPoint({ latitude: null, longitude: null, countryCode: "ZZ" })).toBeNull();
    expect(resolveGeoPoint({ latitude: null, longitude: null, countryCode: null })).toBeNull();
  });

  test("out-of-range event coordinates are rejected, not trusted", () => {
    expect(resolveGeoPoint({ latitude: 400, longitude: 126, countryCode: "KR" })?.source).toBe("country");
    expect(resolveGeoPoint({ latitude: Number.NaN, longitude: 0, countryCode: "KR" })?.source).toBe("country");
  });

  test("haversine distances are plausible", () => {
    const seoul = { latitude: 37.57, longitude: 126.98, source: "event" as const };
    const busan = { latitude: 35.18, longitude: 129.07, source: "event" as const };
    expect(haversineKm(seoul, busan)).toBeGreaterThan(200);
    expect(haversineKm(seoul, seoul)).toBe(0);
  });
});

describe("GeoIP history policy configuration (authentik semantics)", () => {
  test("defaults mirror the authentik GeoIP policy fields", () => {
    const env = envWith(new TestD1());
    expect(geoIpHistoryPolicy(env)).toEqual({
      checkHistoryDistance: false,
      historyMaxDistanceKm: 100,
      distanceToleranceKm: 50,
      historyLoginCount: 5,
      checkImpossibleTravel: true,
      impossibleToleranceKm: 100,
    });
  });

  test("bounds are enforced per field", () => {
    expect(() => geoIpHistoryPolicy({ GEOIP_HISTORY_LOGIN_COUNT: "51" } as unknown as Env))
      .toThrow("GEOIP_HISTORY_LOGIN_COUNT");
    expect(() => geoIpHistoryPolicy({ GEOIP_HISTORY_MAX_DISTANCE_KM: "5" } as unknown as Env))
      .toThrow("GEOIP_HISTORY_MAX_DISTANCE_KM");
    expect(() => geoIpHistoryPolicy({ GEOIP_DISTANCE_TOLERANCE_KM: "abc" } as unknown as Env))
      .toThrow("GEOIP_DISTANCE_TOLERANCE_KM");
    expect(() => geoIpHistoryPolicy({ GEOIP_IMPOSSIBLE_TOLERANCE_KM: "-1" } as unknown as Env))
      .toThrow("GEOIP_IMPOSSIBLE_TOLERANCE_KM");
    expect(() => geoIpHistoryPolicy({ GEOIP_CHECK_IMPOSSIBLE_TRAVEL: "yes" } as unknown as Env))
      .toThrow("GEOIP_CHECK_IMPOSSIBLE_TRAVEL");
  });

  test("the built-in allowance matches authentik's 1,000 km/h", () => {
    expect(IMPOSSIBLE_TRAVEL_KM_PER_HOUR).toBe(1000);
  });
});

describe("evaluateGeoIpHistory core comparisons", () => {
  const busan = { latitude: 35.18, longitude: 129.07, source: "event" as const };
  const seoul = { latitude: 37.57, longitude: 126.98, source: "event" as const };
  const policyDefaults = geoIpHistoryPolicy({} as Env);

  test("history distance check fails beyond max distance plus tolerance", () => {
    // Seoul -> Busan is ~325 km; the 100 + 50 km allowance exceeds that.
    const finding = evaluateGeoIpHistory({
      policy: { ...policyDefaults, checkHistoryDistance: true },
      current: busan,
      history: [{ point: seoul, occurredAt: Date.now() - 2 * 3_600_000 }],
      now: Date.now(),
    });
    expect(finding.reasons).toContain("history_distance_exceeded");
  });

  test("history distance check passes within the allowance", () => {
    const finding = evaluateGeoIpHistory({
      policy: { ...policyDefaults, checkHistoryDistance: true },
      current: seoul,
      history: [{ point: seoul, occurredAt: Date.now() - 2 * 3_600_000 }],
      now: Date.now(),
    });
    expect(finding.reasons).toEqual([]);
  });

  test("impossible travel rounds hours DOWN and adds the tolerance", () => {
    // 59 minutes elapsed: whole-hour clamp keeps the allowance at 1 hour.
    const finding = evaluateGeoIpHistory({
      policy: { ...policyDefaults, checkImpossibleTravel: true },
      current: busan, // ~325 km from Seoul
      history: [{ point: seoul, occurredAt: Date.now() - 59 * 60_000 }],
      now: Date.now(),
    });
    expect(finding.reasons).toEqual([]);

    // 1 hour elapsed, 1,200 km hop: 1200 >= 1000 * 1 + 100 → flagged.
    const tokyo = { latitude: 35.68, longitude: 139.69, source: "event" as const };
    // Seoul -> Tokyo is ~1,150 km.
    const far = evaluateGeoIpHistory({
      policy: { ...policyDefaults, checkImpossibleTravel: true },
      current: tokyo,
      history: [{ point: seoul, occurredAt: Date.now() - 3_600_000 }],
      now: Date.now(),
    });
    expect(far.reasons).toContain("impossible_travel");
  });

  test("long-elapsed hops scale the allowance with elapsed hours", () => {
    const tokyo = { latitude: 35.68, longitude: 139.69, source: "event" as const };
    const finding = evaluateGeoIpHistory({
      policy: { ...policyDefaults, checkImpossibleTravel: true },
      current: tokyo,
      history: [{ point: seoul, occurredAt: Date.now() - 26 * 3_600_000 }],
      now: Date.now(),
    });
    // 26 hours at 1,000 km/h allowance covers the ~1,150 km hop comfortably.
    expect(finding.reasons).toEqual([]);
  });

  test("any compared login failing the check is enough (no lenient averaging)", () => {
    const finding = evaluateGeoIpHistory({
      policy: { ...policyDefaults, checkImpossibleTravel: true },
      current: busan,
      history: [
        { point: busan, occurredAt: Date.now() - 30 * 60_000 },
        { point: { latitude: 39.83, longitude: -98.58, source: "event" as const }, occurredAt: Date.now() - 35 * 60_000 },
      ],
      now: Date.now(),
    });
    expect(finding.reasons).toContain("impossible_travel");
  });
});

describe("login-time GeoIP detection in the risk pipeline", () => {
  test("different device crossing an ocean within an hour is flagged as step_up, not deny", async () => {
    const db = await setup();
    const env = envWith(db);
    const digests = await seedVisitors(env, "u1", ["visitor-old"]);
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-old"]!,
      countryCode: "KR",
      occurredAt: hoursAgo(1),
    });
    const risk = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ visitorId: "visitor-b", countryCode: "US" }),
    });
    expect(risk.reasons).toContain("impossible_travel");
    expect(risk.action).toBe("step_up");
  });

  test("region movement is compared regardless of device (authentik-faithful)", async () => {
    const db = await setup();
    const env = envWith(db);
    const digests = await seedVisitors(env, "u1", ["visitor-a"]);
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-a"]!,
      countryCode: "KR",
      occurredAt: hoursAgo(1),
    });
    const risk = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ countryCode: "US" }),
    });
    expect(risk.reasons).toContain("impossible_travel");
    expect(risk.action).toBe("step_up");
  });

  test("checks can be disabled with GEOIP_CHECK_IMPOSSIBLE_TRAVEL=false", async () => {
    const db = await setup();
    const env = envWith(db, { GEOIP_CHECK_IMPOSSIBLE_TRAVEL: "false" });
    const digests = await seedVisitors(env, "u1", ["visitor-old"]);
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-old"]!,
      countryCode: "KR",
      occurredAt: hoursAgo(1),
    });
    const risk = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ visitorId: "visitor-b", countryCode: "US" }),
    });
    expect(risk.reasons).not.toContain("impossible_travel");
  });

  test("historical login count limits how many logins are compared", async () => {
    const db = await setup();
    const env = envWith(db);
    const digests = await seedVisitors(env, "u1", ["visitor-old"]);

    // Most recent observation is nearby (Busan-ish); an older one is far (US).
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-old"]!,
      latitude: 35.9,
      longitude: 129.4,
      geoSource: "event",
      occurredAt: hoursAgo(0.5),
    });
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-old"]!,
      countryCode: "US",
      occurredAt: hoursAgo(2),
    });

    const countOne = await evaluateFingerprintRisk({
      env: envWith(db, { GEOIP_HISTORY_LOGIN_COUNT: "1" }),
      userId: "u1",
      event: event({ visitorId: "visitor-b", countryCode: null, latitude: 35.98, longitude: 129.5 }),
    });
    expect(countOne.reasons).not.toContain("impossible_travel");

    const countTwo = await evaluateFingerprintRisk({
      env: envWith(db, { GEOIP_HISTORY_LOGIN_COUNT: "2" }),
      userId: "u1",
      event: event({ visitorId: "visitor-b", countryCode: null, latitude: 35.98, longitude: 129.5 }),
    });
    expect(countTwo.reasons).toContain("impossible_travel");
  });

  test("history distance check flags city hops in a calibrated deployment", async () => {
    const db = await setup();
    const env = envWith(db, { GEOIP_CHECK_HISTORY_DISTANCE: "true" });
    const digests = await seedVisitors(env, "u1", ["visitor-old"]);
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-old"]!,
      latitude: 37.57, // Seoul
      longitude: 126.98,
      geoSource: "event",
      occurredAt: hoursAgo(0.5),
    });
    const risk = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ visitorId: "visitor-b", latitude: 35.18, longitude: 129.07 }), // Busan
    });
    expect(risk.reasons).toContain("history_distance_exceeded");
    expect(risk.action).toBe("step_up");

    const near = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ visitorId: "visitor-b", latitude: 37.2, longitude: 127.1 }), // ~45 km south of the prior Seoul login
    });
    expect(near.reasons).not.toContain("history_distance_exceeded");
  });

  test("observations without resolvable points yield geo_position_unavailable (soft failure)", async () => {
    const db = await setup();
    const env = envWith(db);
    const digests = await seedVisitors(env, "u1", ["visitor-old"]);
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-old"]!,
      countryCode: null,
      occurredAt: hoursAgo(1),
    });
    const risk = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ visitorId: "visitor-b", countryCode: null }),
    });
    expect(risk.reasons).toContain("geo_position_unavailable");
    expect(risk.action).toBe("step_up");
  });

  test("rapid-change signals still fire even with history checks disabled", async () => {
    const db = await setup();
    const env = envWith(db, {
      GEOIP_CHECK_IMPOSSIBLE_TRAVEL: "false",
      GEOIP_CHECK_HISTORY_DISTANCE: "false",
    });
    const digests = await seedVisitors(env, "u1", ["visitor-old"]);
    await seedObservation(db, {
      userId: "u1",
      visitorDigest: digests["visitor-old"]!,
      countryCode: "KR",
      occurredAt: hoursAgo(0.2),
    });
    const risk = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ visitorId: "visitor-b", countryCode: "US" }),
    });
    expect(risk.reasons).toContain("rapid_device_and_country_change");
    expect(risk.action).toBe("step_up");
  });

  test("a first login with no history does not flag travel", async () => {
    const db = await setup();
    const env = envWith(db);
    const risk = await evaluateFingerprintRisk({
      env,
      userId: "u1",
      event: event({ visitorId: "visitor-b", countryCode: "US" }),
    });
    expect(risk.reasons).not.toContain("impossible_travel");
    expect(risk.reasons).not.toContain("history_distance_exceeded");
  });
});
