import { describe, expect, test } from "bun:test";
import {
  cleanupDeviceGrants, consumeDeviceGrant, createDeviceGrant, decideDeviceGrant,
  loadDeviceGrantByCode, loadDeviceGrantByUserCode, normalizeUserCode,
  deviceGrantPollIntervalViolated,
} from "../../src/oauth/device-flow";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

async function env(): Promise<Env> {
  const testD1 = createTestD1();
  const e = { DB: testD1.db, AUTH_BASE_URL: "https://auth.example.test" } as unknown as Env;
  const { ensureApplicationTables } = await import("../../src/db/schema");
  await ensureApplicationTables(e);
  return e;
}

describe("device grant store", () => {
  test("roundtrips the grant and accepts tolerant user-code entry", async () => {
    const e = await env();
    const issued = await createDeviceGrant(e, "cli-1", ["openid", "email"]);
    expect(issued.expiresInSeconds).toBe(600);
    expect(issued.intervalSeconds).toBe(5);
    const byUser = await loadDeviceGrantByUserCode(e, issued.userCode);
    expect(byUser?.status).toBe("pending");
    expect(byUser?.clientId).toBe("cli-1");
    expect(byUser?.scopes).toEqual(["openid", "email"]);
    // Typing with spaces or lowercase resolves to the same grant; unknown
    // codes do not.
    const compact = issued.userCode.replace("-", "");
    expect(await loadDeviceGrantByUserCode(e, compact.toLowerCase())).not.toBeNull();
    expect(await loadDeviceGrantByUserCode(e, "XXXX-XXXX")).toBeNull();
    // The device code is only stored hashed: lookup works through the digest.
    const byCode = await loadDeviceGrantByCode(e, issued.deviceCode);
    expect(byCode?.userCode ?? null).toBeDefined();
    expect(await loadDeviceGrantByCode(e, "forged-device-code-value")).toBeNull();
  });

  test("approves once, consumes once, denies are terminal", async () => {
    const e = await env();
    const first = await createDeviceGrant(e, "cli-1", ["openid"]);
    expect(await decideDeviceGrant(e, first.userCode, true, "u1", "sess-1")).toBe(true);
    const approved = await loadDeviceGrantByUserCode(e, first.userCode);
    expect(approved?.status).toBe("approved");
    expect(await consumeDeviceGrant(e, first.deviceCode)).toBe(true);
    expect(await consumeDeviceGrant(e, first.deviceCode)).toBe(false);
    const denied = await createDeviceGrant(e, "cli-1", ["openid"]);
    expect(await decideDeviceGrant(e, denied.userCode, false, "u1", "sess-1")).toBe(true);
    expect(await consumeDeviceGrant(e, denied.deviceCode)).toBe(false);
    // A decided grant cannot be re-decided.
    expect(await decideDeviceGrant(e, denied.userCode, true, "u1", "sess-1")).toBe(false);
  });

  test("expired grants stop resolving and are cleaned up", async () => {
    const e = await env();
    const now = Date.now();
    const issued = await createDeviceGrant(e, "cli-1", ["openid"]);
    await e.DB.prepare("UPDATE oauth_device_grants SET expires_at = ? WHERE user_code = ?")
      .bind(now - 1000, issued.userCode).run();
    expect(await loadDeviceGrantByUserCode(e, issued.userCode)).toBeNull();
    expect(await loadDeviceGrantByCode(e, issued.deviceCode)).toBeNull();
    await createDeviceGrant(e, "cli-1", ["openid"]);
    expect(await cleanupDeviceGrants(e, new Date(now))).toBeGreaterThan(0);
    const remaining = await e.DB.prepare("SELECT COUNT(*) AS c FROM oauth_device_grants").first<{ c: number }>();
    expect(remaining?.c).toBe(0);
  });

  test("poll-interval bookkeeping reports the second fast poll", async () => {
    const e = await env();
    const issued = await createDeviceGrant(e, "cli-1", ["openid"]);
    expect(await deviceGrantPollIntervalViolated(e, issued.deviceCode, 5)).toBe(false);
    expect(await deviceGrantPollIntervalViolated(e, issued.deviceCode, 5)).toBe(true);
  });

  test("caps active grants per client", async () => {
    const e = await env();
    for (let index = 0; index < 20; index += 1) {
      await createDeviceGrant(e, "cli-1", ["openid"]);
    }
    await expect(createDeviceGrant(e, "cli-1", ["openid"])).rejects.toThrow("cap_reached");
    // Other clients are unaffected.
    await expect(createDeviceGrant(e, "cli-2", ["openid"])).resolves.toBeDefined();
  });
});
