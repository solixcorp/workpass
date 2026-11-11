import { beforeAll, describe, expect, test } from "bun:test";
import {
  getOpaqueConfig, KE2, OpaqueClient, OpaqueID, RegistrationResponse, ScryptMemHardFn,
} from "@cloudflare/opaque-ts";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

const ORIGIN = "http://127.0.0.1:8787";
const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const toWire = (bytes: number[]) => {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
const fromWire = (w: string) => Array.from(atob(w.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

function testEnv(db: D1Database): Env {
  const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(5)));
  return {
    DB: db, AUTH_SECRET: "location-opaque-secret-0123456789abcdef-01", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: key, OPAQUE_MASTER_KEY: key,
  } as unknown as Env;
}

const run = (request: Request, env: Env) =>
  mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);

describe("password sign-in and places", () => {
  const { db } = createTestD1();
  const env = testEnv(db);
  const jar = new Map<string, string>();
  let bootstrapBody: any;

  async function call(path: string, init?: { method?: string; body?: unknown; cookies?: boolean; keepJar?: boolean; headers?: Record<string, string>; ip?: string; cf?: Record<string, unknown> }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (init?.cookies !== false && jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    headers["cf-connecting-ip"] = init?.ip ?? "203.0.113.50";
    const outgoing = new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers,
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (init?.cf) Object.defineProperty(outgoing, "cf", { value: init.cf });
    const response = await run(outgoing, env);
    // Sessions of the users under test must not replace the administrator's.
    if (!init?.keepJar) {
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
        if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1));
      }
    }
    return response;
  }

  async function newLink(email: string, name = "New User") {
    const response = await call("/api/admin/users", { method: "POST", body: { email, name, sendEmail: false } });
    expect(response.status).toBe(201);
    const body = await response.json() as any;
    const token = new URL(body.activation.activationUrl).hash.slice(1);
    return { token, userId: body.user.id as string, body };
  }

  async function activate(token: string, email: string, password: string, ip = "203.0.113.50") {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const init = await client.registerInit(password);
    if (init instanceof Error) throw init;
    const start = await call("/api/activation/register/start", {
      method: "POST", cookies: false, ip, body: { token, registrationRequest: toWire(init.serialize()) },
    });
    if (start.status !== 200) return { start };
    const sb = await start.json() as any;
    const fin = await client.registerFinish(
      RegistrationResponse.deserialize(config, fromWire(sb.registrationResponse)), sb.serverIdentity, sb.credentialIdentifier,
    );
    if (fin instanceof Error) throw fin;
    const finish = await call("/api/activation/register/finish", {
      method: "POST", cookies: false, ip, body: { token, record: toWire(fin.record.serialize()) },
    });
    return { start, finish };
  }

  async function opaqueLogin(email: string, password: string, cf?: Record<string, unknown>) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const ke1 = await client.authInit(password);
    if (ke1 instanceof Error) throw ke1;
    const start = await call("/api/opaque/auth/start", { method: "POST", cookies: false, keepJar: true, cf, body: { username: email, ke1: toWire(ke1.serialize()) } });
    const sb = await start.json() as any;
    const done = await client.authFinish(KE2.deserialize(config, fromWire(sb.ke2)), sb.serverIdentity, email).catch((e) => e);
    if (done instanceof Error) return 401;
    const finish = await call("/api/opaque/auth/finish", {
      method: "POST", cookies: false, keepJar: true, cf,
      body: { username: email, ke3: toWire(done.ke3.serialize()), transcriptId: sb.transcriptId },
    });
    return { status: finish.status, body: await finish.json().catch(() => ({})) as any };
  }

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    expect((await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@opaque-loc.test", name: "Admin", username: "oplocadmin", password: "LocOnly-7d9Kpw9zL2xQ" },
    })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "oplocadmin", password: "LocOnly-7d9Kpw9zL2xQ" } })).status).toBe(200);
  });

  test("a password sign-in is refused from outside a place and allowed from inside, and the person is told why", async () => {
    const SEOUL = { latitude: "37.5700", longitude: "126.9800" };
    const BUSAN = { latitude: "35.1796", longitude: "129.0756" };
    const { token } = await newLink("kim@opaque-loc.test", "Kim");
    expect((await activate(token, "kim@opaque-loc.test", "Kim-Password-9x7Qw2Lm")).finish?.status).toBe(200);
    jar.clear();
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "oplocadmin", password: "LocOnly-7d9Kpw9zL2xQ" } })).status).toBe(200);
    await call("/api/admin/location/places", { method: "POST", body: { name: "본사", latitude: 37.5665, longitude: 126.978, radiusM: 500 } });
    expect((await call("/api/admin/location/policy", { method: "PUT", cf: SEOUL, body: { mode: "enforce", signal: "network", networkMarginKm: 30, maxAccuracyM: 1000, exemptGroups: [] } })).status).toBe(200);

    const outside = await opaqueLogin("kim@opaque-loc.test", "Kim-Password-9x7Qw2Lm", BUSAN);
    expect(outside.status).toBe(403);
    expect(outside.body).toMatchObject({ code: "location_denied" });
    const inside = await opaqueLogin("kim@opaque-loc.test", "Kim-Password-9x7Qw2Lm", SEOUL);
    expect(inside.status).toBe(200);
    // A wrong password from outside is still just a wrong password: the place is only named after the proof succeeded.
    expect(await opaqueLogin("kim@opaque-loc.test", "Not-The-Password-1", BUSAN)).toBe(401);
    const logged = await db.prepare("SELECT outcome FROM audit_events WHERE event_type = 'authentication.location.denied'").all<{ outcome: string }>();
    expect(logged.results).toEqual([{ outcome: "failure" }]);
  });
});
