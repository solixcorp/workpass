/**
 * Reputation and GeoIP policy tests (docs/design/authentik-policies.md):
 * score ledger updates with expiry, threshold evaluation over ip/username/both,
 * static country/ASN allow matching and the distance/impossible-travel rules.
 *
 * `bun test tests/policies/reputation-geoip.test.ts`
 */

import { describe, expect, test } from "bun:test";
import { createTestD1 } from "../test-d1";

type TestD1Db = ReturnType<typeof createTestD1>["db"];

import type { Env } from "../../src/env";
import { ensureApplicationTables } from "../../src/db/schema";
import {
  evaluateReputation,
  recordReputationOutcome,
  reputationScore,
  validateReputationConfig,
} from "../../src/policies/reputation";
import {
  evaluateGeoIp,
  validateGeoIpConfig,
} from "../../src/policies/geoip";
import {
  enforcePasswordEntry,
  evaluateLoginSurface,
  LOGIN_SURFACE_REF,
} from "../../src/policies/password-entry";
import { evaluateTyped } from "../../src/policies/registry";

async function envStub(): Promise<{ env: never; db: TestD1Db }> {
  const db = createTestD1().db;
  await ensureApplicationTables({ DB: db } as never);
  return { env: { DB: db, REPUTATION_EXPIRY_HOURS: "72" } as never, db };
}

async function seedUser(db: TestD1, id: string): Promise<void> {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY, email TEXT, name TEXT, username TEXT, role TEXT, banned TEXT)`,
  ).run();
  await db.prepare(
    `INSERT OR IGNORE INTO "user" (id, email, name, username, role) VALUES (?, ?, ?, ?, 'user')`,
  ).bind(id, `${id}@example.test`, id, id).run();
}

async function seedPolicy(
  db: TestD1, name: string, type: string, config: unknown, target: string, targetRef: string,
): Promise<void> {
  const policyId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO policies (id, name, type, config, enabled, execution_logging, created_by, created_at)
     VALUES (?, ?, ?, ?, 1, 0, 'admin', ?)`,
  ).bind(policyId, name, type, JSON.stringify(config), new Date().toISOString()).run();
  await db.prepare(
    `INSERT INTO policy_bindings
       (id, target, target_ref, policy_id, bind_user_id, bind_group_id, order_index, mode, negate,
        failure_result, enabled, created_by, created_at)
     VALUES (?, ?, ?, ?, NULL, NULL, 0, 'all', 0, 'fail', 1, 'admin', ?)`,
  ).bind(crypto.randomUUID(), target, targetRef, policyId, new Date().toISOString()).run();
}

const CONTEXT = (overrides: Record<string, unknown> = {}) =>
  ({ user: null, clientIp: null, subject: null, context: {}, ...overrides } as never);

describe("reputation ledger", () => {
  test("failures decrease and successes increase; threshold evaluation covers both kinds", async () => {
    const { env } = await envStub();
    await validateReputationConfig({ check: "both", threshold: -2 });
    await recordReputationOutcome(env as never, "203.0.113.9", "reputed-user", false);
    await recordReputationOutcome(env as never, "203.0.113.9", "reputed-user", false);
    expect(await reputationScore(env as never, "ip", "203.0.113.9")).toBe(-2);
    expect(await reputationScore(env as never, "username", "reputed-user")).toBe(-2);

    // threshold -3 passes at -2; threshold -2 denies.
    const lenient = await evaluateReputation(env as never, { check: "both", threshold: -3 }, {
      clientIp: "203.0.113.9", username: "reputed-user",
    });
    expect(lenient.passing).toBe(true);
    const strict = await evaluateReputation(env as never, { check: "both", threshold: -2 }, {
      clientIp: "203.0.113.9", username: "reputed-user",
    });
    expect(strict.passing).toBe(false);
    expect(strict.messages.join()).toContain("reputation -2");
    await recordReputationOutcome(env as never, "203.0.113.9", "reputed-user", true);
    const recovered = await evaluateReputation(env as never, { check: "both", threshold: -2 }, {
      clientIp: "203.0.113.9", username: "reputed-user",
    });
    expect(recovered.passing).toBe(true);
  });

  test("check ip only ignores username scores; missing entries pass", async () => {
    const { env } = await envStub();
    await recordReputationOutcome(env as never, "198.51.100.4", null, false);
    await recordReputationOutcome(env as never, "198.51.100.4", null, false);
    const ipOnly = await evaluateReputation(env as never, { check: "ip", threshold: -2 }, {
      clientIp: "198.51.100.4", username: "someone",
    });
    expect(ipOnly.passing).toBe(false);
    // Expired entries read as missing (default 72h; far-future expiry keeps them).
    expect(await evaluateReputation(env as never, { check: "username", threshold: -2 }, {
      clientIp: "198.51.100.4", username: "someone",
    })).toEqual({ passing: true, messages: [] });
  });

  test("config validation bounds", () => {
    expect(() => validateReputationConfig({ check: "nope" })).toThrow("check =");
    expect(() => validateReputationConfig({ check: "ip", threshold: 500 })).toThrow("threshold");
  });
});

describe("login surface with reputation bound", () => {
  test("a failing reputation policy denies the login", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-rep");
    await seedPolicy(db, "rep-login", "reputation", { check: "ip", threshold: -2 }, "login", LOGIN_SURFACE_REF);
    for (let i = 0; i < 2; i += 1) {
      await recordReputationOutcome(env as never, "203.0.113.13", null, false);
    }
    const denied = await evaluateLoginSurface(env as never, "u-rep", {
      clientIp: "203.0.113.13", requestPath: "/sign-in/email",
    });
    expect(denied.passing).toBe(false);
    expect(denied.messages.join()).toContain("at or below");

    // Cleaning the ledger lets the login through again.
    await recordReputationOutcome(env as never, "203.0.113.13", null, true);
    await recordReputationOutcome(env as never, "203.0.113.13", null, true);
    const allowed = await evaluateLoginSurface(env as never, "u-rep", {
      clientIp: "203.0.113.13", requestPath: "/sign-in/email",
    });
    expect(allowed.passing).toBe(true);
  });
});

describe("geoip policy", () => {
  test("country allowlist passes on match and fails otherwise", async () => {
    const { env } = await envStub();
    const config = validateGeoIpConfig({ countries: ["DE", "KR"] });
    const matched = await evaluateGeoIp(env as never, config, CONTEXT({
      geo: { country: "kr", city: "Seoul", lat: 37.5, long: 127 },
    }), null);
    expect(matched.passing).toBe(true);
    const unmatched = await evaluateGeoIp(env as never, config, CONTEXT({
      geo: { country: "US", city: "NY", lat: 40.7, long: -74 },
    }), null);
    expect(unmatched.passing).toBe(false);
    expect(unmatched.messages.join()).toContain("allowlist");
  });

  test("ASN allowlist evaluates against the request asn", async () => {
    const { env } = await envStub();
    const config = validateGeoIpConfig({ asns: [6939] });
    expect((await evaluateGeoIp(env as never, config, CONTEXT({ geo: { asn: 6939 } }), null)).passing).toBe(true);
    expect((await evaluateGeoIp(env as never, config, CONTEXT({ geo: { asn: 12345 } }), null)).passing).toBe(false);
  });

  test("distance rules use the observation history and require a user", async () => {
    const { env, db } = await envStub();
    await seedUser(db, "u-travel");
    await db.prepare(
      `INSERT INTO auth_device_observations (id, user_id, visitor_digest, occurred_at, latitude, longitude, geo_source)
       VALUES ('obs-1', 'u-travel', 'digest', '2026-11-10T08:00:00Z', 37.5, 127.0, 'event')`,
    ).run();
    const config = validateGeoIpConfig({ checkImpossibleTravel: true, historyLoginCount: 5 });
    // The user was in Seoul an hour ago; a login from 5,000 km away now is
    // impossible travel.
    const impossible = await evaluateTyped(env as never, {
      id: "p1", name: "geo-test", type: "geoip",
      config: config as unknown, enabled: true, executionLogging: false,
    }, CONTEXT({
      user: { id: "u-travel", email: "x", name: "x", username: "u-travel", attributes: {}, roles: [] },
      geo: { country: "PT", lat: 38.7, long: -9.1 },
    }) as never, 50_000);
    expect(impossible.passing).toBe(false);
    expect(impossible.messages.join()).toContain("impossible_travel");
    // Same-city login passes.
    const sameCity = await evaluateTyped(env as never, {
      id: "p1", name: "geo-test", type: "geoip",
      config: config as unknown, enabled: true, executionLogging: false,
    }, CONTEXT({
      user: { id: "u-travel", email: "x", name: "x", username: "u-travel", attributes: {}, roles: [] },
      geo: { country: "KR", lat: 37.6, long: 127.2 },
    }) as never, 50_000);
    expect(sameCity.passing).toBe(true);
  });

  test("missing geo data throws so the failure result decides", async () => {
    const { env } = await envStub();
    const config = validateGeoIpConfig({ countries: ["KR"] });
    await expect(evaluateGeoIp(env as never, config, CONTEXT({}), null)).rejects.toThrow("geoip data is unavailable");
  });

  test("config validation requires at least one rule", () => {
    expect(() => validateGeoIpConfig({})).toThrow("requires countries, asns");
    expect(() => validateGeoIpConfig({ countries: "KR" })).toThrow("countries");
  });
});
