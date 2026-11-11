import { beforeAll, describe, expect, test } from "bun:test";
import {
  getOpaqueConfig, KE2, OpaqueClient, OpaqueID, RegistrationResponse, ScryptMemHardFn,
} from "@cloudflare/opaque-ts";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Existing-Passw0rd-7";
const NEW_PASSWORD = "Changed-Passw0rd-8";
const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const toWire = (bytes: number[]) => {
  let value = ""; for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
const fromWire = (value: string) => Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

describe("password link request", () => {
  const { db } = createTestD1();
  const sent: Array<Record<string, unknown>> = [];
  const env = {
    DB: db, AUTH_SECRET: "password-link-test-secret-0123456789abcdef-01", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", INVITATION_EMAIL_WEBHOOK_URL: "https://mail.test/hook",
    INVITATION_EMAIL_FROM: "no-reply@solixcorp.test",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(9))),
    OPAQUE_MASTER_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(9))),
  } as unknown as Env;
  const cookies = new Map<string, string>();
  const pending: Promise<unknown>[] = [];
  const realFetch = globalThis.fetch;
  const testExecution = {
    waitUntil(promise: Promise<unknown>) { pending.push(promise); },
    passThroughOnException() {},
  } as unknown as ExecutionContext;

  async function flush() {
    while (pending.length) await Promise.all(pending.splice(0));
  }

  async function call(path: string, init: { method?: string; body?: unknown; cookies?: boolean; ip?: string; expectBackground?: boolean } = {}) {
    const headers: Record<string, string> = { "cf-connecting-ip": init.ip ?? "203.0.113.81" };
    if (init.cookies !== false && cookies.size) headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    if (init.method && init.method !== "GET") headers.Origin = ORIGIN;
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, {
      method: init.method ?? "GET", headers, body: init.body === undefined ? undefined : JSON.stringify(init.body),
    }), env, testExecution);
    if (init.cookies !== false) {
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
        if (i > 0) cookies.set(pair.slice(0, i), pair.slice(i + 1));
      }
    }
    if (init.expectBackground !== false) await flush();
    return response;
  }

  async function createUser(email: string) {
    const response = await call("/api/admin/users", { method: "POST", body: { email, name: email.split("@")[0], sendEmail: false } });
    expect(response.status).toBe(201);
    const body = await response.json() as any;
    return { userId: body.user.id as string, initialToken: new URL(body.activation.activationUrl).hash.slice(1) };
  }

  async function activate(token: string, email: string, password: string) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const init = await client.registerInit(password);
    if (init instanceof Error) throw init;
    const start = await call("/api/activation/register/start", { method: "POST", cookies: false, body: { token, registrationRequest: toWire(init.serialize()) } });
    expect(start.status).toBe(200);
    const startBody = await start.json() as any;
    const finish = await client.registerFinish(
      RegistrationResponse.deserialize(config, fromWire(startBody.registrationResponse)), startBody.serverIdentity, startBody.credentialIdentifier,
    );
    if (finish instanceof Error) throw finish;
    const result = await call("/api/activation/register/finish", { method: "POST", cookies: false, body: { token, record: toWire(finish.record.serialize()) } });
    expect(result.status).toBe(200);
  }

  async function opaqueLogin(email: string, password: string): Promise<number> {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const ke1 = await client.authInit(password);
    if (ke1 instanceof Error) throw ke1;
    const start = await call("/api/opaque/auth/start", { method: "POST", cookies: false, body: { username: email, ke1: toWire(ke1.serialize()) } });
    const body = await start.json() as any;
    const proof = await client.authFinish(KE2.deserialize(config, fromWire(body.ke2)), body.serverIdentity, email).catch((error) => error);
    if (proof instanceof Error) return 401;
    return (await call("/api/opaque/auth/finish", {
      method: "POST", cookies: false,
      body: { username: email, ke3: toWire(proof.ke3.serialize()), transcriptId: body.transcriptId },
    })).status;
  }

  async function idxSequence(email: string, ip = "203.0.113.81") {
    const introResponse = await call("/idp/idx/introspect", { method: "POST", body: {}, cookies: false, ip });
    expect(introResponse.status).toBe(200);
    const introspect = await introResponse.json() as any;
    const identifyResponse = await call("/idp/idx/identify", { method: "POST", cookies: false, ip, body: { identifier: email, stateHandle: introspect.stateHandle } });
    expect(identifyResponse.status).toBe(200);
    const identify = await identifyResponse.json() as any;
    let challenge = identify;
    if (identify.remediation.value[0].name !== "challenge-authenticator") {
      const passwordId = identify.authenticators.value.find((item: any) => item.key === "password").id;
      const selected = await call("/idp/idx/challenge", { method: "POST", cookies: false, ip, body: { authenticator: { id: passwordId }, stateHandle: identify.stateHandle } });
      expect(selected.status).toBe(200);
      challenge = await selected.json() as any;
    }
    expect(challenge.remediation.value[0].name).toBe("challenge-authenticator");
    expect(challenge.remediation.value[0].ui.alternatives).toContainEqual({
      label: "비밀번호 설정·재설정 링크 받기", action: "request-link", placement: "after", variant: "link",
    });
    return { introspect, identify, challenge };
  }

  function shape(value: any, parentName?: string): any {
    if (Array.isArray(value)) return value.map((entry) => shape(entry));
    if (!value || typeof value !== "object") return value;
    const result: Record<string, unknown> = {};
    const fieldName = typeof value.name === "string" ? value.name : parentName;
    for (const [key, entry] of Object.entries(value)) {
      if (["stateHandle", "expiresAt"].includes(key)) result[key] = `<${key}>`;
      else if (key === "identifier") result[key] = "<identifier>";
      else if (key === "value" && fieldName === "identifier") result[key] = "<identifier>";
      else if (key === "value" && fieldName === "stateHandle") result[key] = "<stateHandle>";
      else result[key] = shape(entry);
    }
    return result;
  }

  async function requestLink(email: string, ip = "203.0.113.82") {
    const sequence = await idxSequence(email, ip);
    const response = await call("/idp/idx/request-link", {
      method: "POST", cookies: false, ip, body: { stateHandle: sequence.challenge.stateHandle },
    });
    return { response, sequence };
  }

  beforeAll(async () => {
    const migrated = await mod.fetch(new Request(`${ORIGIN}/_internal/migrate`, {
      method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` },
    }), env, testExecution);
    expect(migrated.status).toBe(200);
    const clientId = await db.prepare("SELECT value FROM app_settings WHERE key = 'workpass.client_id'").first<{ value: string }>();
    await db.prepare(
      `INSERT INTO app_access_policies (subject, allowed_methods, bypass_window_seconds, enforcement_mode, require_mfa, updated_by, updated_at)
       VALUES (?, 'password', 0, 'enforce', 0, 'test', ?)`,
    ).bind(`oidc:${clientId!.value}`, new Date().toISOString()).run();
    const bootstrap = await mod.fetch(new Request(`${ORIGIN}/api/admin/bootstrap`, {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}`, Origin: ORIGIN, "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@link.test", name: "Admin", username: "linkadmin", password: "LinkAdmin-Password-7" }),
    }), env, testExecution);
    expect(bootstrap.status).toBe(201);
    const signIn = await call("/api/auth/sign-in/username", { method: "POST", body: { username: "linkadmin", password: "LinkAdmin-Password-7" } });
    expect(signIn.status).toBe(200);
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).startsWith("https://mail.test/")) {
        sent.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
        return new Response("ok");
      }
      return realFetch(input, init);
    }) as typeof fetch;
  });

  test("IDX response shape and link request are enumeration-equivalent across account states", async () => {
    const active = await createUser("active@link.test");
    await activate(active.initialToken, "active@link.test", PASSWORD);
    const invited = await createUser("invited@link.test");
    const banned = await createUser("banned@link.test");
    await db.prepare('UPDATE "user" SET banned = 1 WHERE id = ?').bind(banned.userId).run();
    const locked = await createUser("locked@link.test");
    await db.prepare(
      `INSERT INTO account_lockdowns (id, user_id, actor_user_id, source, reason, created_at, lifted_at, lifted_by)
       VALUES (?, ?, ?, 'admin', 'test lockdown', ?, NULL, NULL)`,
    ).bind(crypto.randomUUID(), locked.userId, "test-admin", new Date().toISOString()).run();

    const cases = [
      { email: "missing@link.test", kind: "unknown" },
      { email: "active@link.test", kind: "active" },
      { email: "invited@link.test", kind: "invited" },
      { email: "banned@link.test", kind: "banned" },
      { email: "locked@link.test", kind: "locked" },
    ];
    const before = sent.length;
    const observations = [];
    for (const [index, entry] of cases.entries()) {
      const { response, sequence } = await requestLink(entry.email, `203.0.113.${90 + index}`);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ sent: true });
      observations.push({
        flow: [sequence.introspect, sequence.identify, sequence.challenge].map(shape),
        response: [response.status, await (async () => ({ sent: true }))(), response.headers.get("content-type"), response.headers.get("cache-control")],
      });
    }
    for (const item of observations.slice(1)) expect(item).toEqual(observations[0]);
    expect(sent.length - before).toBe(2);
    for (const message of sent.slice(before)) {
      expect(message.to === "active@link.test" || message.to === "invited@link.test").toBeTrue();
      expect(message.subject).toContain("WorkPass 비밀번호");
      expect(message.text).toContain("로그인 화면에서 요청하신");
      expect(message.text).toContain("요청하지 않으셨다면 이 메일을 무시");
      expect(message.text).toContain(`${ORIGIN}/activate#`);
    }
    for (const userId of [active.userId, invited.userId]) {
      const count = await db.prepare("SELECT COUNT(*) AS count FROM account_activation_tokens WHERE user_id = ? AND used_at IS NULL").bind(userId).first<{ count: number }>();
      expect(count?.count).toBe(1);
    }
    for (const userId of [banned.userId, locked.userId]) {
      const count = await db.prepare("SELECT COUNT(*) AS count FROM account_activation_tokens WHERE user_id = ? AND delivered_to IS NOT NULL").bind(userId).first<{ count: number }>();
      expect(count?.count).toBe(0);
    }
    const missingTokens = await db.prepare("SELECT COUNT(*) AS count FROM account_activation_tokens WHERE delivered_to = 'missing@link.test'").first<{ count: number }>();
    expect(missingTokens?.count).toBe(0);
  });

  test("per-account limit permits three links, suppresses the fourth, and is independent across accounts", async () => {
    const user = await createUser("budget@link.test");
    const other = await createUser("budget-other@link.test");
    const before = sent.length;
    for (let i = 0; i < 4; i += 1) {
      const { response } = await requestLink("budget@link.test", `203.0.114.${i + 1}`);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ sent: true });
    }
    expect(sent.length - before).toBe(3);
    const another = await requestLink("budget-other@link.test", "203.0.114.10");
    expect(another.response.status).toBe(200);
    expect(sent.length - before).toBe(4);
    expect((await db.prepare("SELECT COUNT(*) AS count FROM account_activation_tokens WHERE user_id = ? AND delivered_to IS NOT NULL").bind(user.userId).first<{ count: number }>())?.count).toBe(3);
    expect((await db.prepare("SELECT COUNT(*) AS count FROM account_activation_tokens WHERE user_id = ? AND delivered_to IS NOT NULL").bind(other.userId).first<{ count: number }>())?.count).toBe(1);
  });

  test("emailed links reset an existing password and activate an invited account through OPAQUE", async () => {
    const active = await createUser("reset@link.test");
    await activate(active.initialToken, "reset@link.test", PASSWORD);
    const invited = await createUser("first@link.test");
    for (const email of ["reset@link.test", "first@link.test"]) {
      const before = sent.length;
      await requestLink(email, email.startsWith("reset") ? "203.0.115.1" : "203.0.115.2");
      expect(sent.length).toBe(before + 1);
      const mail = sent.at(-1)!;
      const match = String(mail.text).match(/\/activate#([A-Za-z0-9_-]{40,128})/);
      expect(match).not.toBeNull();
      await activate(match![1]!, email, NEW_PASSWORD);
      expect(await opaqueLogin(email, NEW_PASSWORD)).toBe(200);
      if (email.startsWith("reset")) expect(await opaqueLogin(email, PASSWORD)).toBe(401);
    }
    expect(invited.userId).toBeTruthy();
  });

  test("every valid request is audited, invalid handles are not, and unavailable mail is silent", async () => {
    const known = await createUser("audited@link.test");
    const unknownBefore = await db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'identity.user.link_requested'").first<{ count: number }>();
    await requestLink("unlisted@link.test", "203.0.116.1");
    await requestLink("audited@link.test", "203.0.116.2");
    const invalid = await call("/idp/idx/request-link", { method: "POST", cookies: false, ip: "203.0.116.3", body: { stateHandle: "nope" } });
    expect(invalid.status).toBe(401);
    expect(await invalid.json()).toEqual({
      errorSummary: "세션이 만료되었습니다. 처음부터 다시 시도하세요.",
      messages: { type: "array", value: [{ message: "세션이 만료되었습니다. 처음부터 다시 시도하세요.", class: "ERROR" }] },
    });
    const events = await db.prepare(
      "SELECT target_user_id AS target FROM audit_events WHERE event_type = 'identity.user.link_requested' ORDER BY log_pos",
    ).all<{ target: string | null }>();
    expect(events.results.length - (unknownBefore?.count ?? 0)).toBe(2);
    expect(events.results.slice(-2).map((event) => event.target)).toEqual([null, known.userId]);

    const unavailable = await createUser("no-mail@link.test");
    const noMailBefore = await db.prepare("SELECT COUNT(*) AS count FROM account_activation_tokens WHERE user_id = ?").bind(unavailable.userId).first<{ count: number }>();
    const webhook = env.INVITATION_EMAIL_WEBHOOK_URL;
    (env as unknown as Record<string, unknown>).INVITATION_EMAIL_WEBHOOK_URL = undefined;
    try {
      const result = await requestLink("no-mail@link.test", "203.0.116.4");
      expect(result.response.status).toBe(200);
      expect(await result.response.json()).toEqual({ sent: true });
      const row = await db.prepare("SELECT COUNT(*) AS count FROM account_activation_tokens WHERE user_id = ?").bind(unavailable.userId).first<{ count: number }>();
      expect(row?.count).toBe(noMailBefore?.count);
    } finally {
      (env as unknown as Record<string, unknown>).INVITATION_EMAIL_WEBHOOK_URL = webhook;
    }
  });

  test("expired handles receive the same rejection as identify and challenge", async () => {
    const intro = await (await call("/idp/idx/introspect", { method: "POST", body: {}, cookies: false })).json() as any;
    const identify = await call("/idp/idx/identify", { method: "POST", cookies: false, body: { identifier: "expired@link.test", stateHandle: "invalid" } });
    const challenge = await call("/idp/idx/challenge", { method: "POST", cookies: false, body: { stateHandle: "invalid" } });
    const request = await call("/idp/idx/request-link", { method: "POST", cookies: false, body: { stateHandle: "invalid" } });
    const realNow = Date.now;
    let expired: Response;
    Date.now = () => realNow() + 11 * 60 * 1000;
    try {
      expired = await call("/idp/idx/request-link", { method: "POST", cookies: false, ip: "203.0.117.1", body: { stateHandle: intro.stateHandle } });
    } finally {
      Date.now = realNow;
    }
    expect(intro.stateHandle).toMatch(/^02\.id\./);
    expect(identify.status).toBe(401);
    expect(challenge.status).toBe(401);
    expect(request.status).toBe(401);
    const identifyBody = await identify.json();
    const challengeBody = await challenge.json();
    const requestBody = await request.json();
    expect(identifyBody).toEqual(challengeBody);
    expect(requestBody).toEqual(challengeBody);
    expect(expired!.status).toBe(401);
    expect(await expired!.json()).toEqual(challengeBody);
  });

  test("email delivery stub is restored", () => { globalThis.fetch = realFetch; });
});
