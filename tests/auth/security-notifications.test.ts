import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { notifySecurity } from "../../src/users/notifications";
import { recordLogin } from "../../src/users/login-history";
import { enforceLocationAfterPasskeyLogin } from "../../src/security/location-gate";
import { saveLocationPolicy, DEFAULT_LOCATION_POLICY } from "../../src/security/location-policy";
import { insertAuditEvent } from "../../src/audit/store";
import { getOpaqueConfig, KE2, OpaqueClient, OpaqueID, RegistrationResponse, ScryptMemHardFn } from "@cloudflare/opaque-ts";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Security-7d9Kpw9zL2xQ";
const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const toWire = (bytes: number[]) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const fromWire = (wire: string) => Array.from(atob(wire.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const passwordNotice = { kind: "security_password", title: "비밀번호가 변경되었습니다", body: "본인이 변경한 것이 아니라면 관리자에게 알려주세요.", link: "/security" };
const mfaNotice = (title: string) => ({ kind: "security_mfa", title, body: "보안 설정에서 인증 수단을 확인하세요.", link: "/security" });
const accountNotice = (title: string) => ({ kind: "security_account", title, body: "보안 설정에서 계정 상태를 확인하세요.", link: "/security" });
const locationNotice = { kind: "security_location", title: "허용되지 않은 위치에서 로그인이 시도되었습니다", body: "로그인 활동을 확인하세요.", link: "/activity" };

async function totp(secret: string): Promise<string> {
  let bits = 0, acc = 0;
  const bytes: number[] = [];
  for (const char of secret.replace(/=+$/, "").toUpperCase()) {
    acc = (acc << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char);
    bits += 5;
    if (bits >= 8) { bytes.push((acc >>> (bits - 8)) & 255); bits -= 8; }
  }
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 30000)));
  const key = await crypto.subtle.importKey("raw", new Uint8Array(bytes), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = mac[19]! & 15;
  const number = ((mac[offset]! & 127) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(number % 1_000_000).padStart(6, "0");
}

describe("security notifications", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "security-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))), OPAQUE_MASTER_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))) } as unknown as Env;
  const jar = new Map<string, string>();
  let userId = "";
  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string>; cf?: Record<string, unknown>; cookies?: boolean; keepJar?: boolean }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size && init?.cookies !== false) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET" && !headers.Origin) headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const request = new Request(`${ORIGIN}${path}`, { method: init?.method ?? "GET", headers,
      body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
    if (init?.cf) Object.defineProperty(request, "cf", { value: init.cf });
    const response = await mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of init?.keepJar ? [] : response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i > 0) { const value = pair.slice(i + 1); if (value) jar.set(pair.slice(0, i), value); else jar.delete(pair.slice(0, i)); }
    }
    return response;
  }
  async function notices(id: string, kind?: string) {
    return (await db.prepare("SELECT kind, title, body, link FROM user_notifications WHERE user_id = ? AND (? IS NULL OR kind = ?)").bind(id, kind ?? null, kind ?? null).all<{ kind: string; title: string; body: string; link: string }>()).results;
  }
  async function newUser(email: string) {
    const response = await call("/api/admin/users", { method: "POST", body: { email, name: "Test User", sendEmail: false } });
    expect(response.status).toBe(201);
    const body = await response.json() as any;
    return { id: body.user.id as string, token: new URL(body.activation.activationUrl).hash.slice(1) };
  }
  async function activate(token: string) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const initial = await client.registerInit(PASSWORD);
    if (initial instanceof Error) throw initial;
    const start = await call("/api/activation/register/start", { method: "POST", cookies: false, keepJar: true, body: { token, registrationRequest: toWire(initial.serialize()) } });
    expect(start.status).toBe(200);
    const result = await start.json() as any;
    const finish = await client.registerFinish(RegistrationResponse.deserialize(config, fromWire(result.registrationResponse)), result.serverIdentity, result.credentialIdentifier);
    if (finish instanceof Error) throw finish;
    return call("/api/activation/register/finish", { method: "POST", cookies: false, keepJar: true, body: { token, record: toWire(finish.record.serialize()) } });
  }
  async function opaqueLogin(email: string, cf: Record<string, unknown>) {
    const client = new OpaqueClient(config, ScryptMemHardFn);
    const ke1 = await client.authInit(PASSWORD);
    if (ke1 instanceof Error) throw ke1;
    const start = await call("/api/opaque/auth/start", { method: "POST", cookies: false, keepJar: true, cf, body: { username: email, ke1: toWire(ke1.serialize()) } });
    expect(start.status).toBe(200);
    const result = await start.json() as any;
    const done = await client.authFinish(KE2.deserialize(config, fromWire(result.ke2)), result.serverIdentity, email);
    if (done instanceof Error) throw done;
    return call("/api/opaque/auth/finish", { method: "POST", cookies: false, keepJar: true, cf, body: { username: email, ke3: toWire(done.ke3.serialize()), transcriptId: result.transcriptId } });
  }
  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    const bootstrap = await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` }, body: { email: "admin@security.test", name: "Admin", username: "securityadmin", password: PASSWORD } });
    userId = ((await bootstrap.json()) as any).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "securityadmin", password: PASSWORD } })).status).toBe(200);
  });
  test("activation and password location enforcement notify only after the relevant successful proof", async () => {
    const email = "place@security.test";
    const target = await newUser(email);
    expect((await activate(target.token)).status).toBe(200);
    expect(await notices(target.id, "security_password")).toEqual([passwordNotice]);
    const now = new Date().toISOString();
    await db.prepare("INSERT INTO location_places (id, name, latitude, longitude, radius_m, enabled, created_by, created_at, updated_at) VALUES (?, 'Office', 37, 127, 100, 1, ?, ?, ?)").bind("password-place", userId, now, now).run();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "enforce", signal: "network", networkMarginKm: 0 }, userId);
    try {
      expect((await opaqueLogin(email, { latitude: "37", longitude: "127", country: "KR" })).status).toBe(200);
      expect(await notices(target.id, "security_location")).toEqual([]);
      expect((await opaqueLogin(email, { latitude: "35", longitude: "129", country: "KR" })).status).toBe(403);
      expect(await notices(target.id, "security_location")).toEqual([locationNotice]);
    } finally {
      await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "off" }, userId);
      await db.prepare("DELETE FROM location_places WHERE id = ?").bind("password-place").run();
    }
  });
  test("lockdown, recovery redemption and unlock notify the target, never a failed attempt", async () => {
    const target = await newUser("recovery@security.test");
    const path = `/api/security/account-lockdown/user/${target.id}`;
    expect((await call(`${path}/unlock`, { method: "POST", body: {} })).status).toBe(409);
    expect(await notices(target.id)).toEqual([]);
    expect((await call(path, { method: "POST", body: { reason: "private reason" } })).status).toBe(200);
    expect(await notices(target.id)).toEqual([accountNotice("계정이 잠겼습니다")]);
    const issue = await call("/api/security/account-recovery", { method: "POST", body: { userId: target.id } });
    expect(issue.status).toBe(201);
    const { recoveryToken } = await issue.json() as { recoveryToken: string };
    expect(await notices(target.id, "security_password")).toEqual([]);
    expect((await call("/api/security/account-recovery/redeem", { method: "POST", cookies: false, keepJar: true, body: { token: recoveryToken, new_password: PASSWORD } })).status).toBe(200);
    expect(await notices(target.id, "security_password")).toEqual([passwordNotice]);
    // Recovery itself lifts lockdown; lock once more to exercise the separate unlock endpoint.
    expect((await call(path, { method: "POST", body: { reason: "again" } })).status).toBe(200);
    expect((await call(`${path}/unlock`, { method: "POST", body: {} })).status).toBe(200);
    expect(await notices(target.id, "security_account")).toEqual(expect.arrayContaining([accountNotice("계정이 잠겼습니다"), accountNotice("계정 잠금이 해제되었습니다")]));
  });
  test("confirmed TOTP enrollment and removal notify; an invalid code does not", async () => {
    const enabled = await call("/api/auth/two-factor/enable", { method: "POST", body: { method: "totp", password: PASSWORD } });
    expect(enabled.status).toBe(200);
    const { totpURI } = await enabled.json() as { totpURI: string };
    expect(await notices(userId, "security_mfa")).toEqual([]);
    expect((await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code: "invalid" } })).ok).toBeFalse();
    expect(await notices(userId, "security_mfa")).toEqual([]);
    const code = await totp(new URL(totpURI).searchParams.get("secret")!);
    expect((await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code } })).status).toBe(200);
    expect(await notices(userId, "security_mfa")).toEqual([mfaNotice("2차 인증 수단이 등록되었습니다")]);
    expect((await call("/api/auth/two-factor/disable", { method: "POST", body: { password: PASSWORD } })).status).toBe(200);
    expect(await notices(userId, "security_mfa")).toEqual(expect.arrayContaining([mfaNotice("2차 인증 수단이 삭제되었습니다")]));
    // Keep later HOTP assertions independent of the 60-second dedupe window.
    await db.prepare("DELETE FROM user_notifications WHERE user_id = ? AND kind = 'security_mfa'").bind(userId).run();
  });
  test("passkey registration audit success notifies, but a failed audit does not", async () => {
    // WebAuthn requires an authenticator: exercise the exact audit event finalized by the registration middleware.
    const target = await newUser("passkey@security.test");
    const event = { actor_user_id: target.id, target_user_id: target.id, event_type: "authentication.passkey.registration.success_or_failure", request_path: "/api/auth/passkey/verify-registration" };
    await insertAuditEvent(env, { ...event, id: crypto.randomUUID(), outcome: "failure" });
    expect(await notices(target.id)).toEqual([]);
    await insertAuditEvent(env, { ...event, id: crypto.randomUUID(), outcome: "success" });
    expect(await notices(target.id)).toEqual([mfaNotice("2차 인증 수단이 등록되었습니다")]);
  });
  test("passkey deletion over HTTP notifies only on success", async () => {
    // A stored credential substitutes for hardware registration; deletion itself uses the real HTTP route.
    await db.prepare('INSERT INTO passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp") VALUES (?, ?, ?, ?, 0, ?, 0)')
      .bind("notice-passkey", "test-public-key", userId, "test-credential", "singleDevice").run();
    expect((await call("/api/auth/passkey/delete-passkey", { method: "POST", body: { id: "missing" } })).ok).toBeFalse();
    expect(await notices(userId, "security_mfa")).toEqual([]);
    expect((await call("/api/auth/passkey/delete-passkey", { method: "POST", body: { id: "notice-passkey" } })).status).toBe(200);
    expect(await notices(userId, "security_mfa")).toEqual([mfaNotice("2차 인증 수단이 삭제되었습니다")]);
    await db.prepare("DELETE FROM user_notifications WHERE user_id = ? AND kind = 'security_mfa'").bind(userId).run();
  });
  test("HOTP enrollment and removal notify the affected user", async () => {
    const response = await call("/api/mfa/hotp/enroll", { method: "POST", body: { label: "내 토큰" } });
    expect(response.status).toBe(201);
    const token = await response.json() as { tokenId: string };
    expect((await call(`/api/mfa/hotp/${token.tokenId}`, { method: "DELETE" })).status).toBe(200);
    expect(await notices(userId, "security_mfa")).toEqual(expect.arrayContaining([mfaNotice("2차 인증 수단이 등록되었습니다"), mfaNotice("2차 인증 수단이 삭제되었습니다")]));
  });
  test("administrator actions notify the affected account, not the administrator", async () => {
    const created = await call("/api/admin/users", { method: "POST", body: { email: "target@security.test", name: "Target", sendEmail: false } });
    expect(created.status).toBe(201);
    const target = ((await created.json()) as any).user.id as string;
    for (const [path, body] of [
      ["set-user-password", { userId: target, newPassword: "Changed-7d9Kpw9zL2xQ" }],
      ["set-role", { userId: target, role: "admin" }],
      ["ban-user", { userId: target }],
      ["unban-user", { userId: target }],
      ["revoke-user-sessions", { userId: target }],
    ] as const) expect((await call(`/api/auth/admin/${path}`, { method: "POST", body })).status).toBe(200);
    expect((await call(`/api/security/trusted-devices/user/${target}`, { method: "DELETE" })).status).toBe(200);
    const attach = await call(`/api/admin/users/${target}/mfa/hotp`, { method: "POST", body: { label: "token", secretBase32: "JBSWY3DPEHPK3PXP" } });
    expect(attach.status).toBe(201);
    expect(await notices(target, "security_mfa")).toEqual([mfaNotice("2차 인증 수단이 등록되었습니다")]);
    const token = ((await attach.json()) as any).token.id;
    expect((await call(`/api/admin/users/${target}/mfa/hotp/${token}`, { method: "DELETE" })).status).toBe(200);
    expect(await notices(target, "security_mfa")).toEqual(expect.arrayContaining([mfaNotice("2차 인증 수단이 삭제되었습니다")]));
    await db.prepare("DELETE FROM user_notifications WHERE user_id = ? AND kind = 'security_mfa' AND title = ?").bind(target, "2차 인증 수단이 삭제되었습니다").run();
    expect((await call(`/api/admin/users/${target}/mfa/reset`, { method: "POST" })).status).toBe(200);
    expect(await notices(target)).toEqual(expect.arrayContaining([
      ...["계정 역할이 변경되었습니다", "계정이 비활성화되었습니다", "계정이 활성화되었습니다", "모든 세션이 해제되었습니다", "신뢰 기기가 해제되었습니다"].map(accountNotice),
      mfaNotice("2차 인증 수단이 등록되었습니다"), mfaNotice("2차 인증 수단이 삭제되었습니다"), passwordNotice,
    ]));
  });
  test("security notices deduplicate by user, kind and title for 60 seconds", async () => {
    const notice = { kind: "security_account", title: "테스트", body: "알림", link: "/security" };
    await Promise.all([notifySecurity(env, userId, notice), notifySecurity(env, userId, notice)]);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE title = ?").bind(notice.title).first<{ n: number }>())?.n).toBe(1);
    await db.prepare("UPDATE user_notifications SET created_at = ? WHERE title = ?").bind(new Date(Date.now() - 61_000).toISOString(), notice.title).run();
    await notifySecurity(env, userId, notice);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE title = ?").bind(notice.title).first<{ n: number }>())?.n).toBe(2);
  });
  test("new device and country only alert after the first login", async () => {
    const target = await newUser("device@security.test");
    const request = (agent: string, country: string) => { const r = new Request(ORIGIN, { headers: { "user-agent": agent } }); Object.defineProperty(r, "cf", { value: { country } }); return r; };
    await recordLogin(env, request("Macintosh Chrome/1", "KR"), target.id, "password");
    expect(await notices(target.id, "security_new_device")).toEqual([]);
    await recordLogin(env, request("Macintosh Chrome/2", "KR"), target.id, "password");
    expect(await notices(target.id, "security_new_device")).toEqual([]);
    await recordLogin(env, request("Macintosh Chrome/2", "US"), target.id, "password");
    const rows = await notices(target.id, "security_new_device");
    expect(rows).toEqual([{ kind: "security_new_device", title: "새 기기에서 로그인했습니다", body: "Mac OS X Chrome · US", link: "/activity" }]);
  });
  test("passkey location check preserves or revokes the new session", async () => {
    const row = await db.prepare('SELECT token FROM "session" WHERE "userId" = ? LIMIT 1').bind(userId).first<{ token: string }>();
    expect(row).not.toBeNull();
    const issued = new Response(null, { headers: { "set-cookie": `better-auth.session_token=${row!.token}.signature; Path=/` } });
    const check = (latitude: string, longitude: string) => { const request = new Request(`${ORIGIN}/api/auth/passkey/verify-authentication`); Object.defineProperty(request, "cf", { value: { latitude, longitude } }); return enforceLocationAfterPasskeyLogin(env, request, issued, userId, "/api/auth/passkey/verify-authentication"); };
    await db.prepare("INSERT INTO location_places (id, name, latitude, longitude, radius_m, enabled, created_by, created_at, updated_at) VALUES ('p', 'Office', 37, 127, 100, 1, ?, ?, ?)")
      .bind(userId, new Date().toISOString(), new Date().toISOString()).run();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "observe" }, userId);
    expect(await check("35", "129")).toBeNull();
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(row!.token).first()).not.toBeNull();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "off" }, userId);
    expect(await check("35", "129")).toBeNull();
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "enforce", signal: "network", networkMarginKm: 0 }, userId);
    expect(await check("37", "127")).toBeNull();
    expect(await notices(userId, "security_location")).toEqual([]);
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(row!.token).first()).not.toBeNull();
    const denied = await check("35", "129");
    expect(denied?.status).toBe(403);
    expect(await denied?.json()).toMatchObject({ code: "location_denied" });
    expect(await db.prepare('SELECT token FROM "session" WHERE token = ?').bind(row!.token).first()).toBeNull();
    expect(await notices(userId, "security_location")).toEqual([locationNotice]);
  });
  test("a notification storage failure never breaks the underlying action", async () => {
    await saveLocationPolicy(env, { ...DEFAULT_LOCATION_POLICY, mode: "off" }, userId);
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "securityadmin", password: PASSWORD } })).status).toBe(200);
    await db.prepare("DROP TABLE user_notifications").run();
    expect((await call("/api/mfa/hotp/enroll", { method: "POST", body: { label: "다른 토큰" } })).status).toBe(201);
    expect(await recordLogin(env, { headers: new Headers({ "user-agent": "Linux Firefox/1" }), cf: { country: "GB" } }, userId, "password")).not.toBeNull();
    await notifySecurity(env, userId, { kind: "security_account", title: "테스트", body: "알림" });
  });
});
