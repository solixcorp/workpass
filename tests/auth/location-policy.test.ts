import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** An administrator reads what a user allowed, when, and the device verdict at that moment. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Activity-7d9Kpw9zL2";
const CALLBACK = "https://wiki.example.com/callback";

describe("sign-in places", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", ENABLE_DEVICE_FLOW: "true", ENABLE_CIBA: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";
  let clientId = "";

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string>; cf?: Record<string, unknown>; cookies?: boolean }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size && init?.cookies !== false) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET" && !headers.Origin) headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const outgoing = new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers, redirect: "manual",
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (init?.cf) Object.defineProperty(outgoing, "cf", { value: init.cf });
    const response = await mod.fetch(outgoing, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i <= 0) continue;
      const value = pair.slice(i + 1);
      if (value === "") jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), value);
    }
    return response;
  }
  const json = async (response: Response) => (await response.json()) as any;

  const authorizePath = () => `/api/auth/oauth2/authorize?${new URLSearchParams({
    client_id: clientId, redirect_uri: CALLBACK, response_type: "code", scope: "openid profile email",
    state: "s", code_challenge: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", code_challenge_method: "S256",
  })}`;

  const SEOUL = { latitude: "37.5700", longitude: "126.9800", country: "KR", city: "Seoul" };
  const BUSAN = { latitude: "35.1796", longitude: "129.0756", country: "KR", city: "Busan" };
  const policy = (over: Record<string, unknown>) => ({ mode: "enforce", signal: "network_or_browser", networkMarginKm: 30, maxAccuracyM: 1000, exemptGroups: [], ...over });
  const put = (body: unknown, cf?: Record<string, unknown>) => call("/api/admin/location/policy", { method: "PUT", body, cf });
  const authorize = (cf?: Record<string, unknown>) => call(authorizePath(), { cf });

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@location.test", name: "Admin", username: "locadmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "locadmin", password: PASSWORD } })).status).toBe(200);
    clientId = (await json(await call("/api/admin/oidc-clients", { method: "POST", body: { name: "Wiki", applicationType: "web", redirectUris: [CALLBACK] } }))).client.clientId;
  });

  test("places are checked and kept", async () => {
    const make = (body: unknown) => call("/api/admin/location/places", { method: "POST", body });
    expect((await make({ name: "", latitude: 37.5, longitude: 127, radiusM: 500 })).status).toBe(400);
    expect((await make({ name: "x", latitude: 91, longitude: 127, radiusM: 500 })).status).toBe(400);
    expect((await make({ name: "x", latitude: 37.5, longitude: 127, radiusM: 10 })).status).toBe(400);
    const hq = (await json(await make({ name: "서울 본사", latitude: 37.5665, longitude: 126.978, radiusM: 500 }))).place;
    expect(hq.id).toBeTruthy();
    const edited = await call(`/api/admin/location/places/${hq.id}`, { method: "PUT", body: { name: "서울 본사", latitude: 37.5665, longitude: 126.978, radiusM: 800 } });
    expect(edited.status).toBe(200);
    const view = await json(await call("/api/admin/location"));
    expect(view.places).toMatchObject([{ name: "서울 본사", radiusM: 800, enabled: true }]);
    expect(view.policy.mode).toBe("off");
    expect((await call("/api/admin/location/places/missing", { method: "DELETE" })).status).toBe(404);
  });

  test("a policy cannot lock out the administrator who saves it", async () => {
    expect((await put(policy({ mode: "enforce", signal: "network" }), BUSAN)).status).toBe(409);
    expect((await put(policy({ mode: "enforce", signal: "network" }))).status).toBe(409); // no edge position at all
    expect((await put(policy({ networkMarginKm: 9999 }), SEOUL)).status).toBe(400);
    expect((await put(policy({ mode: "enforce", signal: "network" }), SEOUL)).status).toBe(200);
    expect((await json(await call("/api/admin/location", { cf: SEOUL }))).self).toMatchObject({ pass: true, method: "network", placeName: "서울 본사" });
  });

  test("an app sign-in from outside is turned away, or sent to share a position when that could help", async () => {
    // Network signal only: nothing the browser says can help.
    let outside = await authorize(BUSAN);
    expect(outside.status).toBe(302);
    expect(outside.headers.get("location")).toContain("access_denied");
    expect((await authorize(SEOUL)).headers.get("location")).not.toContain("access_denied");

    expect((await put(policy({ signal: "network_or_browser" }), SEOUL)).status).toBe(200);
    outside = await authorize(BUSAN);
    const where = new URL(outside.headers.get("location")!, ORIGIN);
    expect(where.pathname).toBe("/location");
    expect(where.searchParams.get("redirect")).toContain("/api/auth/oauth2/authorize?");
    const denied = await json(await call("/api/admin/audit-events?eventPrefix=authentication.location.&limit=5"));
    expect(denied.events[0]).toMatchObject({ event_type: "authentication.location.denied", outcome: "failure" });
  });

  test("a browser inside a place is let through for a few minutes, a browser outside is not", async () => {
    const proof = (body: unknown, cf?: Record<string, unknown>) => call("/api/location/proof", { method: "POST", body, cf });
    expect(await json(await proof({ latitude: 35.18, longitude: 129.07, accuracy: 20 }, BUSAN))).toMatchObject({ ok: false, reason: "outside" });
    expect(await json(await proof({ latitude: 37.5665, longitude: 126.978, accuracy: 5000 }, BUSAN))).toMatchObject({ ok: false, reason: "inaccurate" });
    expect((await proof({ latitude: "x", longitude: 1, accuracy: 1 })).status).toBe(400);
    const foreign = await call("/api/location/proof", { method: "POST", body: { latitude: 37.5665, longitude: 126.978, accuracy: 20 }, headers: { Origin: "https://evil.example" } });
    expect(foreign.status).toBe(403);

    expect((await json(await call("/api/location/status", { cf: BUSAN, cookies: false }))).satisfied).toBe(false);
    const ok = await proof({ latitude: 37.5667, longitude: 126.9782, accuracy: 30 }, BUSAN);
    expect(await json(ok)).toEqual({ ok: true });
    expect(ok.headers.get("set-cookie")).toContain("wp_location=");
    expect(ok.headers.get("set-cookie")).toContain("HttpOnly");
    // The cookie jar now carries the proof: the same browser passes from Busan.
    const after = await authorize(BUSAN);
    expect(after.headers.get("location")).not.toContain("/location");
    expect(after.headers.get("location")).not.toContain("access_denied");
    expect((await json(await call("/api/location/status", { cf: BUSAN }))).satisfied).toBe(true);
  });

  test("the sign-in screen asks for a position only when it could help, and can be skipped", async () => {
    const intro = (body: unknown) => call("/idp/idx/introspect", { method: "POST", body, cf: BUSAN, cookies: false });
    const asked = await json(await intro({}));
    expect(asked.remediation.value[0]).toMatchObject({ name: "verify-location", ui: { action: "share-location" } });
    expect((await json(await intro({ skipLocation: true }))).remediation.value[0].name).toBe("identify");
    expect((await json(await call("/idp/idx/introspect", { method: "POST", body: {}, cf: SEOUL, cookies: false }))).remediation.value[0].name).toBe("identify");
    // Network signal only: asking the browser would not help, so the step is not shown.
    await put(policy({ signal: "network" }), SEOUL);
    expect((await json(await intro({}))).remediation.value[0].name).toBe("identify");
  });

  test("an exempt group and observe mode let people through, and observe leaves a trace", async () => {
    const group = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "remote", description: "" } }))).group;
    await call(`/api/admin/directory-groups/${group.id}/members`, { method: "POST", body: { userId: adminId } });
    expect((await put(policy({ signal: "network", exemptGroups: [group.id] }), SEOUL)).status).toBe(200);
    expect((await authorize(BUSAN)).headers.get("location")).not.toContain("access_denied");

    expect((await put(policy({ mode: "observe", signal: "network", exemptGroups: [] }), SEOUL)).status).toBe(200);
    expect((await authorize(BUSAN)).headers.get("location")).not.toContain("access_denied");
    const seen = await json(await call("/api/admin/audit-events?eventPrefix=authentication.location.&limit=1"));
    expect(seen.events[0]).toMatchObject({ event_type: "authentication.location.observe", outcome: "success" });
    expect(JSON.parse(seen.events[0].event_context)).toMatchObject({ reason: "outside", nearestPlace: "서울 본사" });
  });

  test("none of it is open to the wrong caller", async () => {
    jar.clear();
    expect((await call("/api/admin/location")).status).toBe(401);
    expect((await call("/api/admin/location/policy", { method: "PUT", body: policy({}) })).status).toBe(401);
    expect((await call("/api/admin/location/places", { method: "POST", body: { name: "x", latitude: 1, longitude: 1, radiusM: 100 } })).status).toBe(401);
  });
});
