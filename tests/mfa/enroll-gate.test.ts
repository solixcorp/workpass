import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { saveLocationPolicy, DEFAULT_LOCATION_POLICY } from "../../src/security/location-policy";
import { getOpaqueConfig, KE2, OpaqueClient, OpaqueID, RegistrationResponse, ScryptMemHardFn } from "@cloudflare/opaque-ts";

/** Adding a second factor needs a fresh password proof and a second check, bound to the acting session. */

const ORIGIN = "http://127.0.0.1:8787";
const ADMIN_PASSWORD = "GateAdmin-7d9Kpw9zL2xQ";
const PASSWORD = "GateUser-7d9Kpw9zL2xQ";
const EMAIL = "gate@gate.test";
const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const toWire = (bytes: number[]) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const fromWire = (wire: string) => Array.from(atob(wire.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

describe("second-factor enrollment gate", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "gate-secret-0123456789abcdef-0123456789abcdef", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    MFA_OTP_EMAIL_WEBHOOK_URL: "https://otp.test/send",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
    OPAQUE_MASTER_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  const originalFetch = globalThis.fetch;
  let otp = "";
  let sent = 0;

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string>; cookies?: boolean }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size && init?.cookies !== false) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers,
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i <= 0) continue;
      const value = pair.slice(i + 1);
      if (value) jar.set(pair.slice(0, i), value); else jar.delete(pair.slice(0, i));
    }
    return response;
  }

  async function opaqueLogin(email: string, password: string) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const ke1 = await client.authInit(password);
    if (ke1 instanceof Error) throw ke1;
    const start = await call("/api/opaque/auth/start", { method: "POST", cookies: false, body: { username: email, ke1: toWire(ke1.serialize()) } });
    const result = await start.json() as any;
    const done = await client.authFinish(KE2.deserialize(config, fromWire(result.ke2)), result.serverIdentity, email);
    if (done instanceof Error) throw done;
    return call("/api/opaque/auth/finish", { method: "POST", cookies: false, body: { username: email, ke3: toWire(done.ke3.serialize()), transcriptId: result.transcriptId } });
  }

  /** Runs the gate's password exchange; `after` can reuse or swap the transcript. */
  async function confirmPassword(password: string, mutate?: (transcriptId: string) => Promise<string> | string) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const ke1 = await client.authInit(password);
    if (ke1 instanceof Error) throw ke1;
    const start = await call("/api/mfa/gate/password/start", { method: "POST", body: { ke1: toWire(ke1.serialize()) } });
    expect(start.status).toBe(200);
    const result = await start.json() as any;
    const done = await client.authFinish(KE2.deserialize(config, fromWire(result.ke2)), result.serverIdentity, result.credentialIdentifier);
    if (done instanceof Error) return call("/api/mfa/gate/password/finish", { method: "POST", body: { ke3: toWire([1, 2, 3]), transcriptId: result.transcriptId } });
    const transcriptId = mutate ? await mutate(result.transcriptId) : result.transcriptId;
    return call("/api/mfa/gate/password/finish", { method: "POST", body: { ke3: toWire(done.ke3.serialize()), transcriptId } });
  }

  async function enrollment() {
    return await (await call("/api/mfa/enrollment")).json() as any;
  }
  const enable = () => call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp" } });

  beforeAll(async () => {
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      if (String(url).startsWith("https://otp.test/")) {
        otp = (JSON.parse(String(init?.body)) as { otp: string }).otp;
        sent++;
        return new Response(null, { status: 204 });
      }
      return originalFetch(url as RequestInfo, init);
    }) as typeof fetch;
    await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    const bootstrap = await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@gate.test", name: "Admin", username: "gateadmin", password: ADMIN_PASSWORD },
    });
    const adminId = ((await bootstrap.json()) as any).user.id as string;
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "off" }, adminId);
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "gateadmin", password: ADMIN_PASSWORD } })).status).toBe(200);
    const created = await call("/api/admin/users", { method: "POST", body: { email: EMAIL, name: "Gate User", sendEmail: false } });
    expect(created.status).toBe(201);
    const token = new URL(((await created.json()) as any).activation.activationUrl).hash.slice(1);
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const initial = await client.registerInit(PASSWORD);
    if (initial instanceof Error) throw initial;
    const start = await call("/api/activation/register/start", { method: "POST", cookies: false, body: { token, registrationRequest: toWire(initial.serialize()) } });
    const result = await start.json() as any;
    const finish = await client.registerFinish(RegistrationResponse.deserialize(config, fromWire(result.registrationResponse)), result.serverIdentity, result.credentialIdentifier);
    if (finish instanceof Error) throw finish;
    expect((await call("/api/activation/register/finish", { method: "POST", cookies: false, body: { token, record: toWire(finish.record.serialize()) } })).status).toBe(200);
    jar.clear();
    expect((await opaqueLogin(EMAIL, PASSWORD)).status).toBe(200);
  });

  afterAll(() => { globalThis.fetch = originalFetch; });

  test("a session without the reverification cannot add a factor", async () => {
    const view = await enrollment();
    expect(view.verification.required).toBe(true);
    expect(view.verification.steps).toEqual({ passwordOk: false, secondOk: false, secondMode: "email" });
    expect((await enable()).status).toBe(403);
    expect((await call("/api/auth/passkey/generate-register-options")).status).toBe(403);
    expect((await call("/api/mfa/hotp/enroll", { method: "POST", body: { label: "key" } })).status).toBe(403);
    expect((await call("/api/mfa/otp/start", { method: "POST" })).status).toBe(403);
  });

  test("a wrong password, a replayed transcript and a transcript from another session all fail", async () => {
    expect((await confirmPassword("Wrong-7d9Kpw9zL2xQ")).status).toBe(401);
    expect((await enrollment()).verification.steps.passwordOk).toBe(false);

    // A transcript that never existed (stands in for another session's) is refused.
    expect((await confirmPassword(PASSWORD, () => crypto.randomUUID())).status).toBe(401);
    expect((await enrollment()).verification.steps.passwordOk).toBe(false);

    // Moving the transcript to another session of the same user is refused too.
    let issued = "";
    expect((await confirmPassword("Wrong-7d9Kpw9zL2xQ", (id) => { issued = id; return id; })).status).toBe(401);
    const row = await db.prepare("SELECT id FROM mfa_gate_transcripts WHERE id = ?").bind(issued).first();
    expect(row).toBeNull(); // consumed even on failure: single use
  });

  test("the password alone is not enough, and the emailed code alone is not enough", async () => {
    expect((await call("/api/mfa/gate/code/confirm", { method: "POST", body: { code: "000000" } })).status).toBe(400);
    expect((await confirmPassword(PASSWORD)).status).toBe(200);
    const afterPassword = await enrollment();
    expect(afterPassword.verification.steps).toMatchObject({ passwordOk: true, secondOk: false, secondMode: "email" });
    expect((await enable()).status).toBe(403);

    const before = sent;
    expect((await call("/api/mfa/gate/code/start", { method: "POST" })).status).toBe(200);
    expect(sent).toBe(before + 1);
    expect(otp).toMatch(/^[0-9]{6}$/);
    const wrong = otp === "000000" ? "111111" : "000000";
    expect((await call("/api/mfa/gate/code/confirm", { method: "POST", body: { code: wrong } })).status).toBe(400);
    expect((await enable()).status).toBe(403);
    expect((await call("/api/mfa/gate/code/confirm", { method: "POST", body: { code: otp } })).status).toBe(200);
    // The code is single use.
    expect((await call("/api/mfa/gate/code/confirm", { method: "POST", body: { code: otp } })).status).toBe(400);

    const done = await enrollment();
    expect(done.verification.required).toBe(false);
    const enabled = await enable();
    expect(enabled.status).toBe(200);
    expect(await enabled.json()).toMatchObject({ method: "totp" });
  });

  test("the code locks after five wrong tries and expires", async () => {
    jar.clear();
    expect((await opaqueLogin(EMAIL, PASSWORD)).status).toBe(200);
    expect((await call("/api/mfa/gate/code/start", { method: "POST" })).status).toBe(200);
    const good = otp;
    const bad = good === "123456" ? "654321" : "123456";
    for (let i = 0; i < 5; i++) expect((await call("/api/mfa/gate/code/confirm", { method: "POST", body: { code: bad } })).status).toBe(400);
    expect((await call("/api/mfa/gate/code/confirm", { method: "POST", body: { code: good } })).status).toBe(429);
    expect((await enrollment()).verification.steps.secondOk).toBe(false);

    expect((await call("/api/mfa/gate/code/start", { method: "POST" })).status).toBe(200);
    await db.prepare("UPDATE mfa_enroll_gates SET code_expires_at = ?").bind(Date.now() - 1000).run();
    expect((await call("/api/mfa/gate/code/confirm", { method: "POST", body: { code: otp } })).status).toBe(400);
    expect((await enrollment()).verification.steps.secondOk).toBe(false);
  });

  test("an account that holds a real factor cannot use the emailed code instead", async () => {
    const id = (await (await call("/api/auth/get-session")).json() as any).user.id as string;
    await db.prepare("INSERT INTO mfa_hotp_tokens (id, user_id, label, secret_base32, counter, verified, created_at) VALUES ('gate-h', ?, 'key', 'secret', 0, 1, '2026')").bind(id).run();
    const view = await enrollment();
    expect(view.verification.steps.secondMode).toBe("existing");
    expect((await call("/api/mfa/gate/code/start", { method: "POST" })).status).toBe(409);
    await confirmPassword(PASSWORD);
    // Password alone, with a factor on file, still leaves the second check open.
    const after = await enrollment();
    expect(after.verification.steps).toMatchObject({ passwordOk: true, secondOk: false, secondMode: "existing" });
    expect(after.verification.required).toBe(true);
    expect((await enable()).status).toBe(403);
    await db.prepare("DELETE FROM mfa_hotp_tokens WHERE id = 'gate-h'").run();
  });

  test("a second session never inherits another session's reverification", async () => {
    const token = (await (await call("/api/auth/get-session")).json() as any).session.token as string;
    await confirmPassword(PASSWORD);
    expect((await enrollment()).verification.steps.passwordOk).toBe(true);
    const mine = jar.get([...jar.keys()].find((key) => key.endsWith("session_token"))!)!;
    jar.clear();
    expect((await opaqueLogin(EMAIL, PASSWORD)).status).toBe(200);
    expect((await enrollment()).verification.steps.passwordOk).toBe(false);
    expect(mine).toBeTruthy();
    expect(token).toBeTruthy();
  });
});
