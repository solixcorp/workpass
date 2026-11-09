import { describe, expect, test } from "bun:test";
import type { Env } from "../src/env";
import { TestD1 } from "./helpers/test-d1";
import { ensureApplicationTables } from "../src/db/schema";
import {
  bindSessionNetwork,
  cleanupSessionNetworkBindings,
  enforceSessionNetworkBinding,
  isSessionBindingEnforcedPath,
  sessionBindingMode,
  networkBindingLevel,
  geoIpBindingLevel,
  sessionTokenFromRequest,
} from "../src/security/session-geo-binding";
import { digestVisitorId } from "../src/security/fingerprint";

const SECRET = "session-binding-test-secret-0123456789abcdef";

function envWith(db: TestD1, extra: Record<string, string> = {}): Env {
  return {
    DB: db as unknown as Env["DB"],
    AUTH_SECRET: SECRET,
    AUTH_BASE_URL: "https://idp.test",
    SESSION_BINDING_MODE: "enforce",
    SESSION_BINDING_NETWORK: "asn_and_ip",
    SESSION_BINDING_GEOIP: "country_and_city",
    ...extra,
  } as unknown as Env;
}

function requestWith(input: {
  url?: string;
  ip?: string;
  cf?: Record<string, unknown> | null;
  method?: string;
  cookie?: string;
}): Request {
  const headers = new Headers();
  if (input.ip !== undefined) headers.set("cf-connecting-ip", input.ip);
  if (input.cookie !== undefined) headers.set("cookie", input.cookie);
  const request = new Request(input.url ?? "https://idp.test/api/auth/get-session", {
    headers,
    method: input.method ?? "GET",
  });
  if (input.cf !== undefined) {
    Object.defineProperty(request, "cf", { value: input.cf, configurable: true });
  }
  return request;
}

const OFFICE_CF = { asn: 4766, country: "KR", city: "Seoul" };

async function setup(): Promise<TestD1> {
  const db = new TestD1();
  await ensureApplicationTables({ DB: db as unknown as Env["DB"] } as unknown as Env);
  return db;
}

describe("session binding configuration", () => {
  test("mode defaults to disabled and rejects bad values", () => {
    expect(sessionBindingMode({} as Env)).toBe("disabled");
    expect(networkBindingLevel({} as Env)).toBe("off");
    expect(geoIpBindingLevel({} as Env)).toBe("off");
    expect(() => sessionBindingMode({ SESSION_BINDING_MODE: "strict" } as unknown as Env)).toThrow(
      "SESSION_BINDING_MODE",
    );
    expect(() => networkBindingLevel({ SESSION_BINDING_NETWORK: "ip" } as unknown as Env)).toThrow(
      "SESSION_BINDING_NETWORK",
    );
    expect(() => geoIpBindingLevel({ SESSION_BINDING_GEOIP: "city" } as unknown as Env)).toThrow(
      "SESSION_BINDING_GEOIP",
    );
  });

  test("only interactive identity paths are evaluated", () => {
    expect(isSessionBindingEnforcedPath("/api/auth/get-session")).toBe(true);
    expect(isSessionBindingEnforcedPath("/api/auth/oauth2/authorize")).toBe(true);
    expect(isSessionBindingEnforcedPath("/api/auth/sign-in/email")).toBe(false);
    expect(isSessionBindingEnforcedPath("/api/opaque/auth/finish")).toBe(false);
  });

  test("cookie token extraction mirrors Better Auth token scoping", () => {
    const request = requestWith({
      cookie: "better-auth.session_token=abc123.signature; other=1",
    });
    expect(sessionTokenFromRequest(request)).toBe("abc123");
    expect(sessionTokenFromRequest(requestWith({ cookie: "" }))).toBeNull();
  });
});

describe("session binding enforcement", () => {
  test("a bound session passing from the same ASN/network/location is allowed", async () => {
    const db = await setup();
    const env = envWith(db);
    const request = requestWith({ ip: "198.51.100.1", cf: OFFICE_CF });
    expect(await bindSessionNetwork({ env, sessionToken: "tok-1", userId: "u1", request })).toBe(true);

    const sameNetwork = requestWith({ url: "https://idp.test/api/auth/get-session", ip: "198.51.100.1", cf: OFFICE_CF });
    const rejection = await enforceSessionNetworkBinding({
      request: sameNetwork,
      env,
      sessionToken: "tok-1",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect(rejection).toBeNull();
  });

  test("moving to another ASN terminates the session (asn_and_ip level)", async () => {
    const db = await setup();
    const env = envWith(db);
    await bindSessionNetwork({
      env: envWith(db),
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });

    const mobile = requestWith({ url: "https://idp.test/api/auth/get-session", ip: "203.0.113.9", cf: { asn: 45090, country: "KR", city: "Seoul" } });
    const rejection = await enforceSessionNetworkBinding({
      request: mobile,
      env,
      sessionToken: "tok-1",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect(rejection?.status).toBe(401);
    expect((await rejection?.text())?.includes("terminated")).toBe(true);
  });

  test("same ASN but a different IP network terminates at asn_and_ip level", async () => {
    const db = await setup();
    const env = envWith(db, { SESSION_BINDING_NETWORK: "asn_and_ip", SESSION_BINDING_GEOIP: "off" });
    await bindSessionNetwork({
      env,
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    const rejection = await enforceSessionNetworkBinding({
      request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "198.51.100.77", cf: OFFICE_CF }),
      env,
      sessionToken: "tok-1",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect(rejection?.status).toBe(401);
  });

  test("asn-only level tolerates IP/network changes within one ASN", async () => {
    const db = await setup();
    const env = envWith(db, { SESSION_BINDING_NETWORK: "asn", SESSION_BINDING_GEOIP: "off" });
    await bindSessionNetwork({
      env,
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    const rejection = await enforceSessionNetworkBinding({
      request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "198.51.100.77", cf: OFFICE_CF }),
      env,
      sessionToken: "tok-1",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect(rejection).toBeNull();
  });

  test("country drift terminates; city drift only at country_and_city level", async () => {
    const db = await setup();
    const env = envWith(db, { SESSION_BINDING_NETWORK: "off", SESSION_BINDING_GEOIP: "country" });
    await bindSessionNetwork({
      env,
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    expect(
      await enforceSessionNetworkBinding({
        request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "198.51.100.1", cf: { asn: 4766, country: "KR", city: "Busan" } }),
        env,
        sessionToken: "tok-1",
        userId: "u1",
        path: "/api/auth/get-session",
      }),
    ).toBeNull();

    const envWithCity = envWith(db, { SESSION_BINDING_NETWORK: "off", SESSION_BINDING_GEOIP: "country_and_city" });
    const cityBound = await bindSessionNetwork({
      env: envWithCity,
      sessionToken: "tok-2",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    expect(cityBound).toBe(true);
    const cityRejection = await enforceSessionNetworkBinding({
      request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "198.51.100.1", cf: { asn: 4766, country: "KR", city: "Busan" } }),
      env: envWithCity,
      sessionToken: "tok-2",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect(cityRejection?.status).toBe(401);
  });

  test("observe mode records drift without terminating", async () => {
    const db = await setup();
    const env = envWith(db, { SESSION_BINDING_MODE: "observe" });
    await bindSessionNetwork({
      env,
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    for (const path of ["/api/auth/get-session", "/api/auth/get-session", "/api/auth/get-session"]) {
      const rejection = await enforceSessionNetworkBinding({
        request: requestWith({ url: `https://idp.test${path}`, ip: "203.0.113.9", cf: { asn: 45090, country: "KR", city: "Seoul" } }),
        env,
        sessionToken: "tok-1",
        userId: "u1",
        path,
      });
      expect(rejection).toBeNull();
    }
    const events = await db.prepare(`SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'authentication.session.location_drift.observe'`).bind().first<{ n: number }>();
    expect(events?.n).toBe(3);
  });

  test("missing location data on a bound session is a violation in enforce mode", async () => {
    const db = await setup();
    const env = envWith(db, { SESSION_BINDING_NETWORK: "off", SESSION_BINDING_GEOIP: "country" });
    await bindSessionNetwork({
      env,
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    const rejection = await enforceSessionNetworkBinding({
      request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "198.51.100.1", cf: null }),
      env,
      sessionToken: "tok-1",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect(rejection?.status).toBe(401);
  });

  test("an unbound session is allowed (documented rollout deviation)", async () => {
    const db = await setup();
    const env = envWith(db);
    const rejection = await enforceSessionNetworkBinding({
      request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "203.0.113.9", cf: { asn: 45090, country: "US", city: "New York" } }),
      env,
      sessionToken: "never-bound",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect(rejection).toBeNull();
  });

  test("a terminate writes a violation audit event that verifies in the chain", async () => {
    const db = await setup();
    const env = envWith(db);
    await bindSessionNetwork({
      env,
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    await enforceSessionNetworkBinding({
      request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "203.0.113.9", cf: { asn: 45090, country: "KR", city: "Seoul" } }),
      env,
      sessionToken: "tok-1",
      userId: "u1",
      path: "/api/auth/get-session",
    });
    expect((await enforceSessionNetworkBinding({
      request: requestWith({ url: "https://idp.test/api/auth/get-session", ip: "203.0.113.9", cf: { asn: 45090, country: "KR", city: "Seoul" } }),
      env,
      sessionToken: "tok-1",
      userId: "u1",
      path: "/api/auth/get-session",
    }))?.status).toBe(401);
    const { verifyAuditEventChain } = await import("../src/audit/store");
    const verification = await verifyAuditEventChain(env);
    expect(verification.verified).toBe(true);
    expect(verification.entries).toBe(2);
    expect(verification.firstProblem).toBeNull();
    const eventType = await db.prepare(`SELECT event_type FROM audit_events WHERE log_pos = 1`).bind().first<{ event_type: string }>();
    expect(eventType?.event_type).toBe("authentication.session.location_violation");
  });

  test("binding is skipped when disabled or edge data is unavailable", async () => {
    const db = await setup();
    const disabled = envWith(db, { SESSION_BINDING_MODE: "disabled" });
    expect(await bindSessionNetwork({
      env: disabled,
      sessionToken: "tok-off",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    })).toBe(false);

    const enabled = envWith(db);
    // No IP header and no edge context: nothing to compare against later.
    expect(await bindSessionNetwork({
      env: enabled,
      sessionToken: "tok-nocf",
      userId: "u1",
      request: requestWith({ cf: null }),
    })).toBe(false);
    // With network-level data available (the always-present connecting IP) the
    // network envelope is stored even when edge geo context is absent.
    expect(await bindSessionNetwork({
      env: enabled,
      sessionToken: "tok-iponly",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: null }),
    })).toBe(true);

    const rows = await db.prepare(`SELECT COUNT(*) AS n FROM session_network_bindings`).bind().first<{ n: number }>();
    expect(rows?.n).toBe(1);
  });

  test("stored digests never contain the raw network address or city name", async () => {
    const db = await setup();
    const env = envWith(db);
    await bindSessionNetwork({
      env,
      sessionToken: "tok-1",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    const raw = (await db.prepare(`SELECT * FROM session_network_bindings WHERE session_token = 'tok-1'`).bind().first()) as unknown as Record<string, unknown>;
    expect(JSON.stringify(raw)).not.toContain("198.51.100.1");
    expect(JSON.stringify(raw)).not.toContain("Seoul");
    expect(raw.country_code).toBe("KR");
    expect(raw.network_digest).toBe(await digestVisitorId(env, "network:198.51.100.1"));
    expect(raw.city_digest).toBe(await digestVisitorId(env, "city:Seoul"));
  });

  test("cleanup removes only old envelope rows", async () => {
    const db = await setup();
    const env = envWith(db);
    await bindSessionNetwork({
      env,
      sessionToken: "tok-old",
      userId: "u1",
      request: requestWith({ ip: "198.51.100.1", cf: OFFICE_CF }),
    });
    await db.prepare(`UPDATE session_network_bindings SET bound_at = ? WHERE session_token = 'tok-old'`)
      .bind(new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString())
      .run();
    await cleanupSessionNetworkBindings(env, new Date());
    const rows = await db.prepare(`SELECT COUNT(*) AS n FROM session_network_bindings`).bind().first<{ n: number }>();
    expect(rows?.n).toBe(0);
  });
});
