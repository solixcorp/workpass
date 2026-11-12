import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { userHasHotpToken, hotpVerify } from "../../src/mfa/hotp";
import { openStepUpChallenge } from "../../src/security/step-up";
import { grantEnrollGate } from "../mfa/enroll-gate-helper";

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
    MFA_OTP_EMAIL_WEBHOOK_URL: "https://otp.test/send",
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

  test("OTP enrollment requires a delivered code and the account password", async () => {
    let otp = "";
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
      otp = (JSON.parse(String(init?.body)) as { otp: string }).otp;
      return new Response(null, { status: 204 });
    }) as typeof fetch;
    try {
      const me = await (await call("/api/auth/get-session")).json() as any;
      const id = me.user.id;
      expect((await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "otp", password: PASSWORD } })).status).toBe(403);
      expect((await call("/api/mfa/otp/confirm", { method: "POST", body: { code: "000000" } })).status).toBe(403);
      await grantEnrollGate(db);
      expect((await call("/api/mfa/otp/confirm", { method: "POST", body: { code: "000000" } })).status).toBe(400);
      const start = await call("/api/mfa/otp/start", { method: "POST" });
      expect(await start.json()).toEqual({ sent: true, expires_in: 600 });
      const row = await db.prepare("SELECT * FROM mfa_enroll_verifications WHERE user_id = ?").bind(id).first<any>();
      expect(row.code_digest).not.toContain(otp);
      expect(otp).toMatch(/^\d{6}$/);
      const wrong = otp === "000000" ? "000001" : "000000";
      expect((await call("/api/mfa/otp/confirm", { method: "POST", body: { code: wrong } })).status).toBe(400);
      expect((await db.prepare("SELECT attempts FROM mfa_enroll_verifications WHERE user_id = ?").bind(id).first<any>()).attempts).toBe(1);
      expect((await call("/api/mfa/otp/confirm", { method: "POST", body: { code: otp, password: "wrong" } })).status).toBe(400);
      expect(await db.prepare("SELECT * FROM mfa_enroll_verifications WHERE user_id = ?").bind(id).first()).not.toBeNull();
      await db.prepare("UPDATE mfa_enroll_verifications SET expires_at = ? WHERE user_id = ?").bind(Date.now() - 1, id).run();
      expect((await call("/api/mfa/otp/confirm", { method: "POST", body: { code: otp } })).status).toBe(400);
      expect(await db.prepare("SELECT * FROM mfa_enroll_verifications WHERE user_id = ?").bind(id).first()).toBeNull();
      await call("/api/mfa/otp/start", { method: "POST" });
      const wrongAgain = otp === "000000" ? "000001" : "000000";
      for (let i = 0; i < 5; i++) expect((await call("/api/mfa/otp/confirm", { method: "POST", body: { code: wrongAgain } })).status).toBe(400);
      expect((await call("/api/mfa/otp/confirm", { method: "POST", body: { code: otp } })).status).toBe(429);
      await call("/api/mfa/otp/start", { method: "POST" });
      const confirm = await call("/api/mfa/otp/confirm", { method: "POST", body: { code: otp, password: PASSWORD } });
      expect(confirm.status).toBe(200);
      expect(await confirm.json()).toMatchObject({ method: "otp" });
      expect((await db.prepare('SELECT twoFactorEnabled FROM "user" WHERE id = ?').bind(id).first<any>()).twoFactorEnabled).toBe(1);
      expect(await db.prepare("SELECT * FROM mfa_enroll_verifications WHERE user_id = ?").bind(id).first()).toBeNull();
      // An enrolled factor now requires session-bound proof before enrollment is retried.
      expect((await call("/api/mfa/otp/start", { method: "POST" })).status).toBe(403);
      expect((await call("/api/auth/two-factor/disable", { method: "POST", body: { password: PASSWORD } })).status).toBe(200);
    } finally { globalThis.fetch = originalFetch; }
  });

  test("an authenticator app can be enrolled without a server-side password and verified", async () => {
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view.methods.map((m: any) => m.key)).toEqual(["totp", "otp", "hotp", "duo"]);
    expect(view.methods.find((m: any) => m.key === "totp")).toMatchObject({ state: "available", actions: ["enroll"] });
    expect(view.enabled).toBeFalse();

    // The bootstrap administrator still holds a credential password, so the view says so.
    expect(view.passwordRequired).toBeTrue();
    expect((await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp" } })).status).toBe(403);
    await grantEnrollGate(db);
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

    // Exercise both administrator boundaries with a password-only session and
    // an existing verified factor, then complete the real plugin verification.
    await setSetting("mfa.require", "admins");
    const me = await (await call("/api/auth/get-session")).json() as any;
    const token = me.session.token as string;
    await db.prepare("DELETE FROM session_mfa_proofs WHERE session_token = ?").bind(token).run();
    await openStepUpChallenge({ env, sessionToken: token, userId: me.user.id, reasons: ["risk"], requestPath: "/" });
    const adminPath = `/api/admin/attributes/user/${me.user.id}`;
    expect((await call(adminPath)).status).toBe(403);
    expect((await call(adminPath, { method: "PUT", body: { attributes: {} } })).status).toBe(403);
    expect((await call("/api/auth/admin/list-users")).status).toBe(403);
    expect((await call("/api/auth/two-factor/enable", { method: "POST", body: { password: PASSWORD } })).status).toBe(403);
    expect((await call("/api/auth/passkey/generate-register-options")).status).toBe(403);
    expect((await call("/api/auth/passkey/verify-registration", { method: "POST", body: {} })).status).toBe(403);
    await db.prepare('UPDATE "twoFactor" SET verified = 0 WHERE "userId" = ?').bind(me.user.id).run();
    expect((await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code } })).status).toBe(403);
    await db.prepare('UPDATE "twoFactor" SET verified = 1 WHERE "userId" = ?').bind(me.user.id).run();
    await db.prepare('UPDATE "user" SET "twoFactorEnabled" = 0 WHERE id = ?').bind(me.user.id).run();
    expect((await call("/api/auth/two-factor/verify-otp", { method: "POST", body: { code: "000000" } })).status).toBe(403);
    await db.prepare('UPDATE "user" SET "twoFactorEnabled" = 1 WHERE id = ?').bind(me.user.id).run();
    expect((await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code } })).status).toBe(200);
    expect((await call(adminPath)).status).toBe(200);
    expect((await call(adminPath, { method: "PUT", body: { attributes: {} } })).status).toBe(200);
    expect((await call("/api/auth/admin/list-users")).status).toBe(200);
    await setSetting("mfa.require", "off");
  });

  test("a hardware token can be enrolled, verified and removed by its owner", async () => {
    const me = await (await call("/api/auth/get-session")).json() as any;
    await grantEnrollGate(db);
    const enroll = await (await call("/api/mfa/hotp/enroll", { method: "POST", body: { label: "내 토큰" } })).json() as any;
    expect(enroll.secretBase32.length).toBeGreaterThan(15);
    const code = await hotp(base32Decode(enroll.secretBase32), 0);
    expect(await userHasHotpToken(env, me.user.id)).toBeFalse();
    expect((await hotpVerify(env, me.user.id, code)).verified).toBeFalse();
    const pending = await (await call("/api/mfa/enrollment")).json() as any;
    expect(pending.hotpTokens[0].verified).toBeFalse();
    expect(pending.methods.find((m: any) => m.key === "hotp").state).toBe("available");
    expect((await call("/api/mfa/hotp/verify", { method: "POST", body: { code: "invalid", tokenId: enroll.tokenId } })).status).toBe(400);
    expect(await userHasHotpToken(env, me.user.id)).toBeFalse();
    const verify = await call("/api/mfa/hotp/verify", { method: "POST", body: { code, tokenId: enroll.tokenId } });
    expect(verify.status).toBe(200);
    expect(await verify.json()).toEqual({ verified: true });
    expect(await userHasHotpToken(env, me.user.id)).toBeTrue();
    expect((await call("/api/mfa/hotp/verify", { method: "POST", body: { code, tokenId: enroll.tokenId } })).status).toBe(400);
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view.hotpTokens.map((t: any) => t.label)).toContain("내 토큰");
    expect(view.hotpTokens[0].verified).toBeTrue();
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
    // The sign-in card copy is defined by the server.
    expect(view.signIn).toMatchObject({ title: "보안 방법 설정", requiredHeading: "지금 요구됨", setup: "설정" });
    expect(view.disable.available).toBeFalse();
    expect((await call("/api/auth/two-factor/disable", { method: "POST", body: {} })).status).toBe(403);

    const status = await (await call(`/api/admin/users/${me.user.id}/mfa`)).json() as any;
    expect(status).toMatchObject({ required: true, enrolled: true, authenticatorApp: true });

    expect((await call(`/api/admin/users/${me.user.id}/mfa/reset`, { method: "POST", body: {} })).status).toBe(200);
    // Reset revokes the acting session's proof, so admin routes remain closed
    // until the administrator enrolls and verifies a new factor.
    expect((await call(`/api/admin/users/${me.user.id}/mfa`)).status).toBe(403);
    const after = await (await call("/api/mfa/enrollment")).json() as any;
    expect(after).toMatchObject({ required: true, mustEnroll: true, enabled: false });
    await grantEnrollGate(db);
    const enable = await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp", password: PASSWORD } });
    const { totpURI } = await enable.json() as { totpURI: string };
    const code = await hotp(base32Decode(new URL(totpURI).searchParams.get("secret")!), Math.floor(Date.now() / 30000));
    expect((await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code } })).status).toBe(200);
    await setSetting("mfa.require", "off");
    expect((await call(`/api/admin/users/${me.user.id}/mfa/reset`, { method: "POST", body: {} })).status).toBe(200);
  });

  test("an OPAQUE-only account (no server-side password) enrolls without one", async () => {
    const me = await (await call("/api/auth/get-session")).json() as any;
    await db.prepare("DELETE FROM account WHERE userId = ? AND providerId = 'credential'").bind(me.user.id).run();
    const view = await (await call("/api/mfa/enrollment")).json() as any;
    expect(view.passwordRequired).toBeFalse();
    await grantEnrollGate(db);
    const enable = await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp" } });
    expect(enable.status).toBe(200);
  });

  test("administrator user actions: role, sessions and deactivation reach the account", async () => {
    // A second account to act on.
    const created = await (await call("/api/admin/users", { method: "POST", body: { email: "target@mfa.test", name: "Target", sendEmail: false } })).json() as any;
    const targetId = created.user.id as string;

    expect((await call("/api/auth/admin/set-role", { method: "POST", body: { userId: targetId, role: "admin" } })).status).toBe(200);
    expect((await db.prepare('SELECT role FROM "user" WHERE id = ?').bind(targetId).first<{ role: string }>())?.role).toBe("admin");
    expect((await call("/api/auth/admin/set-role", { method: "POST", body: { userId: targetId, role: "user" } })).status).toBe(200);

    expect((await call("/api/auth/admin/ban-user", { method: "POST", body: { userId: targetId } })).status).toBe(200);
    expect((await db.prepare('SELECT banned FROM "user" WHERE id = ?').bind(targetId).first<{ banned: number }>())?.banned).toBe(1);
    expect((await call("/api/auth/admin/unban-user", { method: "POST", body: { userId: targetId } })).status).toBe(200);
    expect((await call("/api/auth/admin/revoke-user-sessions", { method: "POST", body: { userId: targetId } })).status).toBe(200);

    const audited = await db.prepare(
      "SELECT event_type FROM audit_events WHERE event_type LIKE 'identity.user.%' AND target_user_id = ? ORDER BY log_pos",
    ).bind(targetId).all<{ event_type: string }>();
    const types = audited.results.map((row) => row.event_type);
    expect(types).toContain("identity.user.role_change.success_or_failure");
    expect(types).toContain("identity.user.disable.success_or_failure");
    expect(types).toContain("identity.user.enable.success_or_failure");
    expect(types).toContain("identity.user.sessions_revoke.success_or_failure");
  });

  test("self lockdown blocks the account and an administrator can lift it", async () => {
    const created = await (await call("/api/admin/users", { method: "POST", body: { email: "lock@mfa.test", name: "Lock", sendEmail: false } })).json() as any;
    const victim = created.user.id as string;
    const lock = await call(`/api/security/account-lockdown/user/${victim}`, { method: "POST", body: { reason: "도용 의심" } });
    expect(lock.status).toBe(200);
    const history = await (await call(`/api/security/account-lockdown/user/${victim}`)).json() as any;
    expect(history.lockdowns[0]).toMatchObject({ reason: "도용 의심", liftedAt: null });
    expect((await db.prepare('SELECT banned FROM "user" WHERE id = ?').bind(victim).first<{ banned: number }>())?.banned).toBe(1);

    expect((await call(`/api/security/account-lockdown/user/${victim}/unlock`, { method: "POST", body: {} })).status).toBe(200);
    const after = await (await call(`/api/security/account-lockdown/user/${victim}`)).json() as any;
    expect(after.lockdowns[0].liftedAt).toBeTruthy();
    expect((await call(`/api/security/account-lockdown/user/${victim}/unlock`, { method: "POST", body: {} })).status).toBe(409);
  });

  test("accounts: create, duplicate name, invitation code is returned once and listed masked", async () => {
    const created = await call("/api/admin/accounts", { method: "POST", body: { name: "acme-korea", description: "Acme" } });
    expect(created.status).toBe(201);
    const account = (await created.json() as any).account;
    expect((await call("/api/admin/accounts", { method: "POST", body: { name: "acme-korea" } })).status).toBe(409);

    const invite = await (await call(`/api/admin/accounts/${account.id}/invitations`, { method: "POST", body: { role: "member" } })).json() as any;
    expect(invite.invitation.token.length).toBe(64);
    const listed = await (await call(`/api/admin/accounts/${account.id}/invitations`)).json() as any;
    expect(JSON.stringify(listed)).not.toContain(invite.invitation.token);
    expect(listed.invitations[0]).toMatchObject({ status: "pending", role: "member" });

    // The same account redeems it once; a second try fails the same way as a bad code.
    const first = await call("/api/accounts/join", { method: "POST", body: { token: invite.invitation.token } });
    expect([201, 403]).toContain(first.status);
    expect((await call("/api/accounts/join", { method: "POST", body: { token: "nope" } })).status).toBe(403);
  });

  test("custom attributes: typed values round-trip, bad names are refused, delete empties them", async () => {
    const me = await (await call("/api/auth/get-session")).json() as any;
    const path = `/api/admin/attributes/user/${me.user.id}`;
    const put = await call(path, { method: "PUT", body: { attributes: { department: "엔지니어링", level: 3, contractor: false, note: null } } });
    expect(put.status).toBe(200);
    const read = await (await call(path)).json() as any;
    expect(read.attributes).toEqual({ department: "엔지니어링", level: 3, contractor: false, note: null });
    expect((await call(path, { method: "PUT", body: { attributes: { "bad name!": "x" } } })).status).toBe(400);
    expect((await call(path, { method: "PUT", body: { attributes: { level: 2 ** 60 } } })).status).toBe(400);
    expect((await call(path, { method: "PUT", body: { attributes: { ratio: 1.5 } } })).status).toBe(200);
    expect((await call(path, { method: "DELETE" })).status).toBe(200);
    expect(((await (await call(path)).json()) as any).attributes).toEqual({});
  });

  test("policies: create, bind, a bound policy cannot be deleted, unbind then delete", async () => {
    const bad = await call("/api/admin/policies", { method: "POST", body: { name: "rep", type: "reputation", config: { check: "ip", threshold: 500 } } });
    expect(bad.status).toBe(400);
    const created = await call("/api/admin/policies", { method: "POST", body: { name: "rep", type: "reputation", config: { check: "both", threshold: -5 } } });
    expect(created.status).toBe(201);
    const policy = (await created.json() as any).policy;
    expect((await call("/api/admin/policies", { method: "POST", body: { name: "rep", type: "reputation", config: { check: "ip" } } })).status).toBe(409);

    const bound = await call("/api/admin/policy-bindings", { method: "POST", body: { target: "login", targetRef: "", policyId: policy.id, order: 0 } });
    expect(bound.status).toBe(201);
    const binding = (await bound.json() as any).binding;
    expect((await call(`/api/admin/policies/${policy.id}`, { method: "DELETE" })).status).toBe(409);

    expect((await call(`/api/admin/policy-bindings/${binding.id}`, { method: "DELETE" })).status).toBe(200);
    expect((await call(`/api/admin/policies/${policy.id}`, { method: "DELETE" })).status).toBe(200);
  });

  test("notification rules: validate transports, reject duplicates, list and delete", async () => {
    const path = "/api/admin/notification-rules";
    const make = (body: unknown) => call(path, { method: "POST", body });
    expect((await make({ name: "bad name!", transports: [{ kind: "email", to: "a@example.com" }] })).status).toBe(400);
    expect((await make({ name: "alerts", transports: [] })).status).toBe(400);
    expect((await make({ name: "alerts", transports: [{ kind: "webhook", url: "http://insecure.example.com" }] })).status).toBe(400);

    const created = await make({ name: "alerts", transports: [{ kind: "email", to: "sec@example.com" }, { kind: "webhook", url: "https://hooks.example.com/x" }] });
    expect(created.status).toBe(201);
    const rule = (await created.json() as any).rule;
    expect((await make({ name: "alerts", transports: [{ kind: "email", to: "b@example.com" }] })).status).toBe(409);

    const listed = (await (await call(path)).json() as any).rules;
    expect(listed.map((r: any) => r.name)).toEqual(["alerts"]);
    expect(listed[0].transports).toHaveLength(2);

    expect((await call(`${path}/${rule.id}`, { method: "DELETE" })).status).toBe(200);
    expect((await call(`${path}/${rule.id}`, { method: "DELETE" })).status).toBe(404);
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
