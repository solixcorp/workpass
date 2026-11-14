import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { evaluateFingerprintRisk, verifyFingerprintEvent } from "../../src/security/fingerprint";

const env = {
  AUTH_SECRET: "fingerprint-test-secret",
  AUTH_BASE_URL: "https://idp.test",
  FINGERPRINT_SERVER_API_KEY: "test",
  GEOIP_CHECK_IMPOSSIBLE_TRAVEL: "false",
  DB: { prepare: () => ({ bind: () => ({ first: async () => ({ id: "trusted" }), all: async () => ({ results: [] }) }) }) },
} as unknown as Env;

async function parse(extra: Record<string, unknown>) {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => Response.json({
    event_id: "event", timestamp: Date.now(), url: "https://idp.test/login",
    identification: { visitor_id: "visitor", confidence: { score: 0.99 } },
    ...extra,
  })) as typeof fetch;
  try {
    return await verifyFingerprintEvent({ env, eventId: "event", request: new Request("https://idp.test") });
  } finally {
    globalThis.fetch = original;
  }
}

describe("Fingerprint Smart Signals", () => {
  test("accepts all signals and both IP versions", async () => {
    const { event } = await parse({
      vpn: { vpn: true }, proxy: { proxy: true }, virtual_machine: { virtual_machine: true },
      incognito: true, developer_tools: true, privacy_settings: true, simulator: true,
      rare_device: true, high_activity_device: true,
      ip_blocklist: { tor_node: true, attack_source: true, email_spam: true, extra: 1 },
      ip_info: { v4: { asn: "1", datacenter_result: false, geolocation: { country_code: "US" } }, v6: { asn: "2", datacenter_result: true } },
    });
    expect(event).toMatchObject({ vpn: true, proxy: true, virtualMachine: true, incognito: true, developerTools: true, privacySettings: true, simulator: true, rareDevice: true, highActivityDevice: true, torNode: true, attackSource: true, emailSpam: true, asnV4: "1", asnV6: "2", datacenterIp: true, countryCode: "US" });
    const risk = await evaluateFingerprintRisk({ env, userId: "user", event: event! });
    expect(risk.action).toBe("deny");
    expect(risk.reasons).toHaveLength(12);
  });

  const invalid: Array<Record<string, unknown>> = [
    { vpn: { vpn: "true" } }, { vpn: [] }, { proxy: { proxy: 1 } },
    { virtual_machine: { virtual_machine: null } },
    ...["incognito", "developer_tools", "privacy_settings", "simulator", "rare_device", "high_activity_device"].map((key) => ({ [key]: "true" })),
    ...["tor_node", "attack_source", "email_spam"].map((key) => ({ ip_blocklist: { [key]: 1 } })),
    { ip_blocklist: [] }, { ip_info: { v4: { asn: 5 } } },
    { ip_info: { v6: { datacenter_result: "true" } } },
  ];
  test.each(invalid)("rejects malformed signal %#", async (value) => {
    expect((await parse(value)).error).toBe("invalid_event");
  });

  const cases: Array<[Record<string, unknown>, string, string]> = [
    [{ vpn: true }, "vpn_detected", "step_up"],
    [{ proxy: true }, "proxy_detected", "step_up"],
    [{ incognito: true }, "incognito_detected", "allow"],
    [{ privacy_settings: true }, "privacy_settings_detected", "step_up"],
    [{ rare_device: true }, "rare_device_detected", "step_up"],
    [{ high_activity_device: true }, "high_activity_device_detected", "step_up"],
    [{ simulator: true }, "simulator_detected", "step_up"],
    [{ ip_info: { v6: { datacenter_result: true } } }, "datacenter_ip_detected", "step_up"],
    [{ ip_blocklist: { tor_node: true } }, "tor_network_detected", "deny"],
    [{ ip_blocklist: { attack_source: true } }, "ip_blocklisted", "deny"],
    [{ virtual_machine: true }, "virtual_machine_detected", "step_up"],
    [{ tampering: true }, "tampering_detected", "step_up"],
    [{ developer_tools: true }, "developer_tools_detected", "allow"],
  ];
  test.each(cases)("classifies signal %#", async (raw, reason, action) => {
    const { event } = await parse(raw);
    expect(event).not.toBeNull();
    const risk = await evaluateFingerprintRisk({ env, userId: "user", event: event! });
    expect(risk.action).toBe(action);
    expect(risk.reasons).toEqual([reason]);
  });

  test("ignores retired signals and emits no reasons for absent signals", async () => {
    for (const raw of [{}, { mitm_attack: true, location_spoofing: { obsolete: true } }]) {
      const { event } = await parse(raw);
      expect(event).not.toBeNull();
      const risk = await evaluateFingerprintRisk({ env, userId: "user", event: event! });
      expect(risk.action).toBe("allow");
      expect(risk.reasons).toEqual([]);
    }
  });
});
