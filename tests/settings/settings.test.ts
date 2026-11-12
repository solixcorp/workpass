import { beforeAll, describe, expect, spyOn, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { normalizeSettingValue, settingDefinition } from "../../src/settings/registry";
import { createTestD1 } from "../test-d1";
import { applySettings, invalidateSettings, resolveSettings, saveSetting } from "../../src/settings/store";
import { ensureApplicationTables } from "../../src/db/schema";
import { mfaPolicy, passkeyAllowed } from "../../src/mfa/policy";

const ORIGIN = "http://127.0.0.1:8787";

function testEnv(db: D1Database): Env {
  return {
    DB: db,
    AUTH_SECRET: "settings-test-secret-0123456789abcdef-012345",
    AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true",
    MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true",
    ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    FINGERPRINT_PUBLIC_API_KEY: "public-key-for-tests",
    FINGERPRINT_REGION: "eu",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
  } as unknown as Env;
}

const run = (request: Request, env: Env) =>
  mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);

describe("normalizeSettingValue", () => {
  test("enforces the registry's types and ranges", () => {
    const ttl = settingDefinition("activation.token_ttl_minutes")!;
    expect(normalizeSettingValue(ttl, 60)).toBe("60");
    expect(normalizeSettingValue(ttl, " 90 ")).toBe("90");
    expect(() => normalizeSettingValue(ttl, 1)).toThrow();
    expect(() => normalizeSettingValue(ttl, 999999)).toThrow();
    expect(() => normalizeSettingValue(ttl, 10.5)).toThrow();
    expect(() => normalizeSettingValue(ttl, "abc")).toThrow();
    const mode = settingDefinition("fingerprint.mode")!;
    expect(normalizeSettingValue(mode, "observe")).toBe("observe");
    expect(() => normalizeSettingValue(mode, "yolo")).toThrow();
  });
});

describe("settings read failures", () => {
  async function fixture() {
    const { db } = createTestD1();
    let failing = false;
    let reads = 0;
    const env = testEnv(new Proxy(db, { get(target, key) {
      if (key === "prepare") return (sql: string) => {
        if (sql.includes("FROM app_settings")) {
          reads++;
          if (failing) throw new Error("D1 temporarily unavailable");
        }
        return target.prepare(sql);
      };
      return Reflect.get(target, key);
    } }));
    env.FINGERPRINT_MODE = "disabled";
    await ensureApplicationTables(env);
    return { env, fail(value: boolean) { failing = value; }, reads: () => reads };
  }

  test("cold read failure rejects requests, is not cached, and recovers", async () => {
    const f = await fixture();
    f.fail(true);
    await expect(applySettings(f.env)).rejects.toThrow("unavailable");
    await expect(resolveSettings(f.env)).rejects.toThrow("unavailable");
    const response = await run(new Request(`${ORIGIN}/api/config/login`), f.env);
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: "Internal server error" });
    expect(f.reads()).toBe(3);
    f.fail(false);
    await saveSetting(f.env, "fingerprint.mode", "enforce", "admin");
    expect((await applySettings(f.env)).FINGERPRINT_MODE).toBe("enforce");
  });

  test("expired cache and forced refresh retain administrator security overrides", async () => {
    const f = await fixture();
    for (const [key, value] of [
      ["fingerprint.mode", "enforce"], ["mfa.require", "everyone"],
      ["login.allow_passkey", "off"], ["mfa.allow_totp", "off"],
      ["step_up.challenge_ttl_seconds", "300"], ["activation.token_ttl_minutes", "5"],
    ]) await saveSetting(f.env, key!, value!, "admin");
    await applySettings(f.env);
    f.fail(true);
    const now = Date.now();
    const clock = spyOn(Date, "now").mockReturnValue(now + 31_000);
    try {
      const effective = await applySettings(f.env);
      expect(effective.FINGERPRINT_MODE).toBe("enforce");
      expect(mfaPolicy(effective)).toMatchObject({ require: "everyone", allow: { totp: false } });
      expect(passkeyAllowed(effective)).toBe(false);
      expect(effective.STEP_UP_CHALLENGE_TTL_SECONDS).toBe("300");
      expect(effective.ACTIVATION_TOKEN_TTL_MINUTES).toBe("5");
      const reads = f.reads();
      await applySettings(f.env);
      expect(f.reads()).toBe(reads); // outage retry is also bounded by the TTL
      expect((await resolveSettings(f.env)).find((s) => s.definition.key === "fingerprint.mode"))
        .toMatchObject({ value: "enforce", source: "admin" });
      invalidateSettings(f.env);
      expect((await applySettings(f.env)).MFA_REQUIRE).toBe("everyone");
      f.fail(false);
      await saveSetting(f.env, "fingerprint.mode", "observe", "admin");
      expect((await applySettings(f.env)).FINGERPRINT_MODE).toBe("observe");
    } finally {
      clock.mockRestore();
    }
  });

  test("explicit missing table permits migration but never caches startup defaults", async () => {
    const { db } = createTestD1();
    const env = testEnv(db);
    expect(await applySettings(env)).toBe(env);
    await ensureApplicationTables(env);
    await db.prepare("INSERT INTO app_settings (key, value, updated_by, updated_at) VALUES ('fingerprint.mode', 'enforce', 'admin', 'now')").run();
    expect((await applySettings(env)).FINGERPRINT_MODE).toBe("enforce");
    await db.prepare("DROP TABLE app_settings").run();
    invalidateSettings(env);
    expect((await applySettings(env)).FINGERPRINT_MODE).toBe("enforce");
  });
});

describe("admin settings", () => {
  const { db } = createTestD1();
  const env = testEnv(db);
  const jar = new Map<string, string>();

  async function call(path: string, init?: { method?: string; body?: unknown; origin?: boolean; headers?: Record<string, string>; cookies?: boolean }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (init?.cookies !== false && jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.origin !== false && init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await run(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET",
      headers,
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const i = pair.indexOf("=");
      if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return response;
  }

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    expect((await call("/api/admin/bootstrap", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@settings.test", name: "Admin", username: "setadmin", password: "SettingsOnly-7d9Kpw9zL2" },
    })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", {
      method: "POST", body: { username: "setadmin", password: "SettingsOnly-7d9Kpw9zL2" },
    })).status).toBe(200);
  });

  test("requires an administrator", async () => {
    expect((await call("/api/admin/settings", { cookies: false })).status).toBe(401);
    expect((await call("/api/admin/settings/step_up.challenge_ttl_seconds", {
      method: "PUT", cookies: false, body: { value: 600 },
    })).status).toBe(401);
  });

  test("lists the registry with each value's source", async () => {
    const body = await (await call("/api/admin/settings")).json() as any;
    expect(body.groups.map((g: any) => g.id)).toContain("step-up");
    const ttl = body.settings.find((s: any) => s.key === "step_up.challenge_ttl_seconds");
    expect(ttl).toMatchObject({ value: "900", source: "default", unit: "초", min: 300, max: 3600 });
    const confidence = body.settings.find((s: any) => s.key === "fingerprint.min_confidence");
    expect(confidence.step).toBe(0.05);
  });

  test("a stored value overrides the default, is audited, and can be reset", async () => {
    const put = await call("/api/admin/settings/step_up.challenge_ttl_seconds", { method: "PUT", body: { value: 600 } });
    expect(put.status).toBe(200);
    let body = await (await call("/api/admin/settings")).json() as any;
    expect(body.settings.find((s: any) => s.key === "step_up.challenge_ttl_seconds")).toMatchObject({ value: "600", source: "admin" });

    const audited = await db.prepare(
      "SELECT outcome FROM audit_events WHERE event_type = 'admin.setting.updated' ORDER BY log_pos DESC LIMIT 1",
    ).first<{ outcome: string }>();
    expect(audited?.outcome).toBe("success");

    expect((await call("/api/admin/settings/step_up.challenge_ttl_seconds", { method: "DELETE" })).status).toBe(200);
    body = await (await call("/api/admin/settings")).json() as any;
    expect(body.settings.find((s: any) => s.key === "step_up.challenge_ttl_seconds")).toMatchObject({ value: "900", source: "default" });
  });

  test("rejects unknown keys and out-of-range values", async () => {
    expect((await call("/api/admin/settings/AUTH_SECRET", { method: "PUT", body: { value: "x" } })).status).toBe(404);
    expect((await call("/api/admin/settings/step_up.challenge_ttl_seconds", { method: "PUT", body: { value: 5 } })).status).toBe(400);
    expect((await call("/api/admin/settings/fingerprint.mode", { method: "PUT", body: { value: "bogus" } })).status).toBe(400);
  });

  test("device-risk checks cannot be switched on without the server key", async () => {
    const response = await call("/api/admin/settings/fingerprint.mode", { method: "PUT", body: { value: "enforce" } });
    expect(response.status).toBe(409);
  });

  test("enforcement needs a recorded device check for the acting admin, and a break-glass switch turns checks off", async () => {
    env.FINGERPRINT_SERVER_API_KEY = "server-key-for-tests";
    const refused = await call("/api/admin/settings/fingerprint.mode", { method: "PUT", body: { value: "enforce" } });
    expect(refused.status).toBe(409);
    expect(((await refused.json()) as { error: string }).error).toContain("관찰");

    // Observe mode is always allowed; it is how the proof gets recorded.
    expect((await call("/api/admin/settings/fingerprint.mode", { method: "PUT", body: { value: "observe" } })).status).toBe(200);
    const me = await (await call("/api/auth/get-session")).json() as { user: { id: string } };
    await db.prepare(
      "INSERT INTO fingerprint_risk_decisions (id, user_id, event_id, action, reasons, request_path, occurred_at) VALUES ('d1', ?, 'evt-1', 'observe', '[]', '/p', ?)",
    ).bind(me.user.id, new Date().toISOString()).run();
    expect((await call("/api/admin/settings/fingerprint.mode", { method: "PUT", body: { value: "enforce" } })).status).toBe(200);

    // Operator recovery: the deployment flag wins over the stored setting.
    const { applySettings } = await import("../../src/settings/store");
    expect((await applySettings(env)).FINGERPRINT_MODE).toBe("enforce");
    const recovered = await applySettings({ ...env, FINGERPRINT_BREAK_GLASS: "true" } as typeof env);
    expect(recovered.FINGERPRINT_MODE).toBe("disabled");
    expect((await call("/api/admin/settings/fingerprint.mode", { method: "DELETE" })).status).toBe(200);
    delete (env as { FINGERPRINT_SERVER_API_KEY?: string }).FINGERPRINT_SERVER_API_KEY;
  });

  test("the organization name is a validated text setting that reaches the login config", async () => {
    expect((await call("/api/admin/settings/organization.name", { method: "PUT", body: { value: "" } })).status).toBe(400);
    expect((await call("/api/admin/settings/organization.name", { method: "PUT", body: { value: "x".repeat(65) } })).status).toBe(400);
    expect((await call("/api/admin/settings/organization.name", { method: "PUT", body: { value: "  Acme Korea  " } })).status).toBe(200);
    const config = await (await call("/api/config/login", { cookies: false })).json() as any;
    expect(config.organization.name).toBe("Acme Korea");
    expect((await call("/api/admin/settings/organization.name", { method: "DELETE" })).status).toBe(200);
  });

  test("a stored value reaches the request handlers (login config reads the overridden mode)", async () => {
    const before = await (await call("/api/config/login", { cookies: false })).json() as any;
    expect(before.fingerprint).toBeNull();
    env.FINGERPRINT_SERVER_API_KEY = "server-key-for-tests";
    expect((await call("/api/admin/settings/fingerprint.mode", { method: "PUT", body: { value: "observe" } })).status).toBe(200);
    const after = await (await call("/api/config/login", { cookies: false })).json() as any;
    expect(after.fingerprint).toEqual({ publicKey: "public-key-for-tests", region: "eu", endpoint: null });
    expect((await call("/api/admin/settings/fingerprint.mode", { method: "DELETE" })).status).toBe(200);
    const reset = await (await call("/api/config/login", { cookies: false })).json() as any;
    expect(reset.fingerprint).toBeNull();
  });
});
