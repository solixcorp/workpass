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
    DB: db, AUTH_SECRET: "activation-test-secret-0123456789abcdef-01", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: key, OPAQUE_MASTER_KEY: key,
  } as unknown as Env;
}

const run = (request: Request, env: Env) =>
  mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);

describe("account activation", () => {
  const { db } = createTestD1();
  const env = testEnv(db);
  const jar = new Map<string, string>();

  async function call(path: string, init?: { method?: string; body?: unknown; cookies?: boolean; keepJar?: boolean; headers?: Record<string, string>; ip?: string }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (init?.cookies !== false && jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    headers["cf-connecting-ip"] = init?.ip ?? "203.0.113.50";
    const response = await run(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers,
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env);
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

  async function opaqueLogin(email: string, password: string) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const ke1 = await client.authInit(password);
    if (ke1 instanceof Error) throw ke1;
    const start = await call("/api/opaque/auth/start", { method: "POST", cookies: false, keepJar: true, body: { username: email, ke1: toWire(ke1.serialize()) } });
    const sb = await start.json() as any;
    const done = await client.authFinish(KE2.deserialize(config, fromWire(sb.ke2)), sb.serverIdentity, email).catch((e) => e);
    if (done instanceof Error) return 401;
    const finish = await call("/api/opaque/auth/finish", {
      method: "POST", cookies: false, keepJar: true,
      body: { username: email, ke3: toWire(done.ke3.serialize()), transcriptId: sb.transcriptId },
    });
    return finish.status;
  }

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    expect((await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@activation.test", name: "Admin", username: "actadmin", password: "ActivationOnly-7d9Kpw9zL2" },
    })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", {
      method: "POST", body: { username: "actadmin", password: "ActivationOnly-7d9Kpw9zL2" },
    })).status).toBe(200);
  });

  test("only administrators can create users or issue links", async () => {
    expect((await call("/api/admin/users", { method: "POST", cookies: false, body: { email: "x@y.test", name: "X" } })).status).toBe(401);
    expect((await call("/api/admin/users/abc/activation-link", { method: "POST", cookies: false, body: {} })).status).toBe(401);
  });

  test("full path: create, inspect, set a password, then sign in normally", async () => {
    const { token, userId, body } = await newLink("new.user@activation.test");
    expect(body.activation.emailed).toBeFalse();
    expect(body.activation.activationUrl).toContain("/activate#");

    const inspect = await (await call("/api/activation/inspect", { method: "POST", cookies: false, body: { token } })).json() as any;
    expect(inspect.email).toBe("new.user@activation.test");
    expect(inspect.ui.title).toBe("비밀번호 설정");
    expect(inspect.ui.requirements.length).toBeGreaterThan(0);
    expect(inspect.ui.rules.minLength).toBeGreaterThanOrEqual(8);

    // Before activation there is no way to sign in.
    expect(await opaqueLogin("new.user@activation.test", "Brand-New-Passw0rd")).toBe(401);

    const { finish } = await activate(token, "new.user@activation.test", "Brand-New-Passw0rd");
    expect(finish!.status).toBe(200);
    expect(finish!.headers.get("set-cookie")).toBeNull();

    expect(await opaqueLogin("new.user@activation.test", "Brand-New-Passw0rd")).toBe(200);
    expect(await opaqueLogin("new.user@activation.test", "Wrong-Passw0rd-xx")).toBe(401);

    const audited = await db.prepare(
      "SELECT outcome FROM audit_events WHERE event_type = 'identity.user.activation.completed' AND target_user_id = ?",
    ).bind(userId).first<{ outcome: string }>();
    expect(audited?.outcome).toBe("success");
  });

  test("a link works once", async () => {
    const { token } = await newLink("once@activation.test");
    expect((await activate(token, "once@activation.test", "First-Passw0rd-1")).finish!.status).toBe(200);
    const again = await activate(token, "once@activation.test", "Second-Passw0rd-2");
    expect(again.start.status).toBe(404);
    expect(await opaqueLogin("once@activation.test", "First-Passw0rd-1")).toBe(200);
    expect(await opaqueLogin("once@activation.test", "Second-Passw0rd-2")).toBe(401);
  });

  test("unknown, malformed and expired links get one identical answer", async () => {
    const { token, userId } = await newLink("expired@activation.test");
    await db.prepare("UPDATE account_activation_tokens SET expires_at = ? WHERE user_id = ?")
      .bind(new Date(Date.now() - 1000).toISOString(), userId).run();
    const answers = [];
    for (const candidate of [token, "A".repeat(43), "short", 12345]) {
      const response = await call("/api/activation/inspect", { method: "POST", cookies: false, body: { token: candidate } });
      answers.push([response.status, await response.text()]);
    }
    expect(new Set(answers.map((entry) => entry.join("|"))).size).toBe(1);
    expect(answers[0]![0]).toBe(404);
  });

  test("issuing a new link closes the previous one", async () => {
    const first = await newLink("reissue@activation.test");
    const response = await call(`/api/admin/users/${first.userId}/activation-link`, { method: "POST", body: { sendEmail: false } });
    expect(response.status).toBe(200);
    const second = new URL(((await response.json()) as any).activation.activationUrl).hash.slice(1);
    expect((await call("/api/activation/inspect", { method: "POST", cookies: false, body: { token: first.token } })).status).toBe(404);
    expect((await call("/api/activation/inspect", { method: "POST", cookies: false, body: { token: second } })).status).toBe(200);
  });

  test("activating an existing account revokes its sessions", async () => {
    const { token, userId } = await newLink("sessions@activation.test");
    await db.prepare(
      `INSERT INTO "session" (id, "expiresAt", token, "createdAt", "updatedAt", "userId") VALUES ('s-1', ?, 'tok-1', ?, ?, ?)`,
    ).bind(new Date(Date.now() + 1e7).toISOString(), new Date().toISOString(), new Date().toISOString(), userId).run();
    expect((await activate(token, "sessions@activation.test", "Fresh-Passw0rd-3")).finish!.status).toBe(200);
    const left = await db.prepare('SELECT COUNT(*) AS count FROM "session" WHERE "userId" = ?').bind(userId).first<{ count: number }>();
    expect(left?.count).toBe(0);
  });

  test("admin password rules drive the activation screen and are audited", async () => {
    const before = await (await call("/api/admin/password-rules")).json() as any;
    expect(before.fields.map((f: any) => f.name)).toEqual(["minLength", "minUpper", "minLower", "minDigit", "minSymbol"]);
    expect(before.stored).toBeFalse();
    expect(before.fields.find((f: any) => f.name === "minLength").value).toBe(12);

    const put = await call("/api/admin/password-rules", { method: "PUT", body: { values: { minLength: 16, minSymbol: 2 } } });
    expect(put.status).toBe(200);
    const after = await (await call("/api/admin/password-rules")).json() as any;
    expect(after.stored).toBeTrue();
    expect(after.effective).toMatchObject({ minLength: 16, minSymbol: 2 });

    const { token } = await newLink("rules@activation.test");
    const inspect = await (await call("/api/activation/inspect", { method: "POST", cookies: false, body: { token } })).json() as any;
    expect(inspect.ui.rules).toMatchObject({ minLength: 16, minSymbol: 2 });
    expect(inspect.ui.requirements).toContain("16자 이상");
    expect(inspect.ui.requirements).toContain("기호 2개 이상");

    // Out-of-range and non-integer values never reach the engine.
    expect((await call("/api/admin/password-rules", { method: "PUT", body: { values: { minLength: 4 } } })).status).toBe(400);
    expect((await call("/api/admin/password-rules", { method: "PUT", body: { values: { minUpper: 1.5 } } })).status).toBe(400);
    expect((await call("/api/admin/password-rules", { method: "PUT", cookies: false, body: { values: {} } })).status).toBe(401);

    const audited = await db.prepare(
      "SELECT outcome FROM audit_events WHERE event_type = 'policy.password_rules.update' ORDER BY log_pos DESC LIMIT 1",
    ).first<{ outcome: string }>();
    expect(audited?.outcome).toBe("success");

    // Restore the defaults for the remaining tests.
    await call("/api/admin/password-rules", { method: "PUT", body: { values: { minLength: 12, minSymbol: 0 } } });
  });

  test("duplicate emails are refused and the link TTL follows the admin setting", async () => {
    const dup = await call("/api/admin/users", { method: "POST", body: { email: "new.user@activation.test", name: "Dup", sendEmail: false } });
    expect(dup.status).toBe(409);
    expect((await call("/api/admin/settings/activation.token_ttl_minutes", { method: "PUT", body: { value: 10 } })).status).toBe(200);
    const { body } = await newLink("ttl@activation.test");
    const minutes = (Date.parse(body.activation.expiresAt) - Date.now()) / 60_000;
    expect(minutes).toBeGreaterThan(8);
    expect(minutes).toBeLessThanOrEqual(10.1);
  });
});
