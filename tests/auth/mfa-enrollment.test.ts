import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** Second-factor enrollment and the administrator's controls, against a real Better Auth. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "MfaOnly-7d9Kpw9zL2";

function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, acc = 0;
  const out: number[] = [];
  for (const char of value.toUpperCase().replace(/=+$/, "")) {
    acc = (acc << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) { out.push((acc >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

async function hotp(secret: Uint8Array, counter: number): Promise<string> {
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = mac[19]! & 0xf;
  const code = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(code % 1_000_000).padStart(6, "0");
}

describe("second-factor enrollment", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "mfa-test-secret-0123456789abcdef-0123456", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string> }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers, redirect: "manual",
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i <= 0) continue;
      const value = pair.slice(i + 1);
      if (value === "") jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), value);
    }
    return response;
  }

  async function signIn() {
    jar.clear();
    const response = await call("/api/auth/sign-in/username", { method: "POST", body: { username: "mfaadmin", password: PASSWORD } });
    expect(response.status).toBe(200);
  }

  async function setSetting(key: string, value: string) {
    const response = await call(`/api/admin/settings/${key}`, { method: "PUT", body: { value } });
    expect(response.status).toBe(200);
    // The overlay cache lives 30s; the route invalidates it for this isolate.
  }

  beforeAll(async () => {
    await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@mfa.test", name: "Admin", username: "mfaadmin", password: PASSWORD },
    });
    await signIn();
  });

  test("an authenticator app can be enrolled without a server-side password and verified", async () => {
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view.methods.map((m: any) => m.key)).toEqual(["totp", "otp", "hotp", "duo"]);
    expect(view.methods.find((m: any) => m.key === "totp")).toMatchObject({ state: "available", actions: ["enroll"] });
    expect(view.enabled).toBeFalse();

    // The bootstrap administrator still holds a credential password, so the view says so.
    expect(view.passwordRequired).toBeTrue();
    expect((await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp" } })).status).toBe(400);
    const enable = await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp", password: PASSWORD } });
    expect(enable.status).toBe(200);
    const { totpURI, backupCodes } = await enable.json() as { totpURI: string; backupCodes: string[] };
    expect(totpURI.startsWith("otpauth://totp/")).toBeTrue();
    expect(backupCodes.length).toBeGreaterThan(5);

    const secret = new URL(totpURI).searchParams.get("secret")!;
    const code = await hotp(base32Decode(secret), Math.floor(Date.now() / 30000));
    const verify = await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code } });
    expect(verify.status).toBe(200);

    const after = await (await call("/api/mfa/enrollment")).json() as any;
    expect(after.enabled).toBeTrue();
    expect(after.methods.find((m: any) => m.key === "totp").state).toBe("enrolled");
    expect(after.backupCodes.available).toBeTrue();
  });

  test("a hardware token can be enrolled, verified and removed by its owner", async () => {
    const enroll = await (await call("/api/mfa/hotp/enroll", { method: "POST", body: { label: "내 토큰" } })).json() as any;
    expect(enroll.secretBase32.length).toBeGreaterThan(15);
    const code = await hotp(base32Decode(enroll.secretBase32), 0);
    const verify = await call("/api/mfa/hotp/verify", { method: "POST", body: { code } });
    expect(verify.status).toBe(200);
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view.hotpTokens.map((t: any) => t.label)).toContain("내 토큰");
    expect((await call(`/api/mfa/hotp/${enroll.tokenId}`, { method: "DELETE" })).status).toBe(200);
  });

  test("the administrator can switch methods off and the server refuses them", async () => {
    await setSetting("mfa.allow_otp", "off");
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view.methods.find((m: any) => m.key === "otp").state).toBe("blocked");
    expect((await call("/api/auth/two-factor/send-otp", { method: "POST", body: {} })).status).toBe(403);
    await setSetting("mfa.allow_otp", "on");

    await setSetting("login.allow_passkey", "off");
    expect((await call("/api/auth/passkey/generate-authenticate-options", { method: "POST", body: {} })).status).toBe(403);
    const identify = await (await call("/idp/idx/introspect", { method: "POST", body: {} })).json() as any;
    expect(identify.remediation.value[0].ui.alternatives).toEqual([]);
    await setSetting("login.allow_passkey", "on");
  });

  test("a required second factor cannot be turned off, and reset clears everything", async () => {
    await setSetting("mfa.require", "admins");
    const me = await (await call("/api/auth/get-session")).json() as any;
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view).toMatchObject({ required: true, mustEnroll: false, enabled: true });
    expect(view.disable.available).toBeFalse();
    expect((await call("/api/auth/two-factor/disable", { method: "POST", body: {} })).status).toBe(403);

    const status = await (await call(`/api/admin/users/${me.user.id}/mfa`)).json() as any;
    expect(status).toMatchObject({ required: true, enrolled: true, authenticatorApp: true });

    expect((await call(`/api/admin/users/${me.user.id}/mfa/reset`, { method: "POST", body: {} })).status).toBe(200);
    const cleared = await (await call(`/api/admin/users/${me.user.id}/mfa`)).json() as any;
    expect(cleared).toMatchObject({ enrolled: false, authenticatorApp: false, hotpTokens: [] });
    const after = await (await call("/api/mfa/enrollment")).json() as any;
    expect(after).toMatchObject({ required: true, mustEnroll: true, enabled: false });
    await setSetting("mfa.require", "off");
  });

  test("an OPAQUE-only account (no server-side password) enrolls without one", async () => {
    const me = await (await call("/api/auth/get-session")).json() as any;
    await db.prepare("DELETE FROM account WHERE userId = ? AND providerId = 'credential'").bind(me.user.id).run();
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view.passwordRequired).toBeFalse();
    const enable = await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp" } });
    expect(enable.status).toBe(200);
  });

  test("an administrator can attach a hardware token seed for a user", async () => {
    const me = await (await call("/api/auth/get-session")).json() as any;
    const bad = await call(`/api/admin/users/${me.user.id}/mfa/hotp`, { method: "POST", body: { label: "x", secretBase32: "short" } });
    expect(bad.status).toBe(400);
    const ok = await call(`/api/admin/users/${me.user.id}/mfa/hotp`, { method: "POST", body: { label: "YubiKey", secretBase32: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" } });
    expect(ok.status).toBe(201);
    const status = await (await call(`/api/admin/users/${me.user.id}/mfa`)).json() as any;
    expect(status.hotpTokens).toHaveLength(1);
  });
});
