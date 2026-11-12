import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { gradeDeviceTrust, latestObservations } from "../../src/security/device-trust";
import { fingerprintSignalSnapshot } from "../../src/security/fingerprint";

describe("device trust grading", () => {
  test("a clean allowed sign-in is trusted and soft reasons lower the score", () => {
    expect(gradeDeviceTrust("allow", [])).toEqual({ level: "trusted", score: 95 });
    const soft = gradeDeviceTrust("allow", ["vpn_detected", "incognito_detected", "rare_device_detected"]);
    expect(soft.level).toBe("normal");
    expect(soft.score).toBe(80);
  });

  test("step-up verdicts are capped at review and hard reasons are risky", () => {
    expect(gradeDeviceTrust("step_up", ["untrusted_device"]).level).toBe("review");
    expect(gradeDeviceTrust("allow", ["tor_network_detected"]).level).toBe("risky");
    expect(gradeDeviceTrust("deny", ["bot_detected"]).level).toBe("risky");
    expect(gradeDeviceTrust("deny", ["bot_detected"]).score).toBeLessThan(30);
  });

  test("no recorded verdict is reported as unknown, not as safe", () => {
    expect(gradeDeviceTrust(null, [])).toEqual({ level: "unknown", score: 0 });
  });
});

describe("recorded fingerprint observations", () => {
  test("snapshot keeps provider signals but never the raw visitor id or address", () => {
    const snapshot = fingerprintSignalSnapshot({
      visitorId: "raw-visitor-id", ip: "203.0.113.9", confidence: 0.9, suspectScore: 3, vpn: true, tampering: false,
      countryCode: "KR", eventOrigin: "https://auth.example.test", timestamp: 1,
    } as never);
    const text = JSON.stringify(snapshot);
    expect(text).not.toContain("raw-visitor-id");
    expect(text).not.toContain("203.0.113.9");
    expect(snapshot).toMatchObject({ confidence: 0.9, suspectScore: 3, vpn: true, countryCode: "KR" });
  });

  test("the latest observation per digest drives the grade and an empty table degrades quietly", async () => {
    const { db } = createTestD1();
    const env = { DB: db } as unknown as Env;
    expect((await latestObservations(env, "u1", ["d1"])).size).toBe(0);

    await db.prepare(
      `CREATE TABLE auth_device_observations (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, visitor_digest TEXT NOT NULL, occurred_at TEXT NOT NULL,
        risk_action TEXT, risk_reasons TEXT, signals TEXT)`,
    ).run();
    const insert = (id: string, digest: string, at: string, action: string, reasons: string[], user = "u1") =>
      db.prepare("INSERT INTO auth_device_observations (id, user_id, visitor_digest, occurred_at, risk_action, risk_reasons, signals) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(id, user, digest, at, action, JSON.stringify(reasons), JSON.stringify({ vpn: reasons.includes("vpn_detected") })).run();
    await insert("a", "d1", "2026-01-01T00:00:00.000Z", "deny", ["bot_detected"]);
    await insert("b", "d1", "2026-02-01T00:00:00.000Z", "allow", []);
    await insert("c", "d2", "2026-02-01T00:00:00.000Z", "step_up", ["untrusted_device"]);
    await insert("d", "d1", "2026-03-01T00:00:00.000Z", "deny", ["bot_detected"], "other-user");

    const result = await latestObservations(env, "u1", ["d1", "d2", "missing"]);
    expect(result.get("d1")?.level).toBe("trusted");
    expect(result.get("d2")?.level).toBe("review");
    expect(result.get("d2")?.reasons).toEqual(["untrusted_device"]);
    expect(result.has("missing")).toBe(false);
  });
});
