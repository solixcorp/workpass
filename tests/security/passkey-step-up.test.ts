import { beforeAll, describe, expect, spyOn, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { appMfaChallenge, openStepUpChallenge, getStepUpChallenge, usableSecondFactors } from "../../src/security/step-up";
import { createAuth } from "../../src/auth/config";

const ORIGIN = "http://127.0.0.1:8787";
const enc = new TextEncoder();
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const concat = (...parts: Uint8Array[]) => new Uint8Array(Buffer.concat(parts));

describe("session-bound passkey step-up", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "detail-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))) } as unknown as Env;
  const jar = new Map<string, string>();
  let userId = "";
  let token = "";
  let privateKey: CryptoKey;
  let publicKey = "";
  const credentialId = b64url(crypto.getRandomValues(new Uint8Array(32)));
  async function call(path: string, body?: unknown, anonymous = false, cookies = jar) {
    const headers: Record<string, string> = { Origin: ORIGIN, "Content-Type": "application/json" };
    if (!anonymous) headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await mod.fetch(new Request(`${ORIGIN}${path}`, { method: "POST", headers, body: JSON.stringify(body ?? {}) }), env,
      { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of res.headers.getSetCookie()) { const pair = cookie.split(";")[0]!; const i = pair.indexOf("="); if (i > 0) cookies.set(pair.slice(0, i), pair.slice(i + 1)); }
    return res;
  }
  const options = () => call("/api/security/step-up/passkey/options");
  const verify = (body: unknown, anonymous = false) => call("/api/security/step-up/passkey/verify", body, anonymous);
  async function assertion(challenge: string, flags = 5) {
    const client = enc.encode(JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN }));
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("127.0.0.1")));
    const data = concat(hash, new Uint8Array([flags, 0, 0, 0, 1]));
    const signed = concat(data, new Uint8Array(await crypto.subtle.digest("SHA-256", client)));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, signed));
    const integer = (a: Uint8Array) => { let i = 0; while (i < a.length - 1 && a[i] === 0) i++; const v = a.slice(i); return concat(new Uint8Array([2, v.length + ((v[0]! & 128) ? 1 : 0)]), (v[0]! & 128) ? new Uint8Array([0]) : new Uint8Array(), v); };
    const r = integer(raw.slice(0, 32)), s = integer(raw.slice(32));
    const signature = concat(new Uint8Array([0x30, r.length + s.length]), r, s);
    return { id: credentialId, rawId: credentialId, type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: b64url(client), authenticatorData: b64url(data), signature: b64url(signature) } };
  }
  beforeAll(async () => {
    const setup = async (path: string, bearer: string, body: unknown) => mod.fetch(new Request(`${ORIGIN}${path}`, { method: "POST", headers: { Origin: ORIGIN, Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" }, body: JSON.stringify(body) }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    expect((await setup("/_internal/migrate", env.MIGRATION_TOKEN!, {})).status).toBe(200);
    const created = await setup("/api/admin/bootstrap", env.ADMIN_BOOTSTRAP_TOKEN!, { email: "admin@passkey.test", name: "Admin", username: "passkeyadmin", password: "SelfSvc-7d9Kpw9zL2xQ" });
    userId = ((await created.json()) as any).user.id;
    expect((await call("/api/auth/sign-in/username", { username: "passkeyadmin", password: "SelfSvc-7d9Kpw9zL2xQ" })).status).toBe(200);
    token = (await db.prepare('SELECT token FROM "session" WHERE "userId" = ?').bind(userId).first<{ token: string }>())!.token;
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]); privateKey = pair.privateKey;
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const cose = concat(new Uint8Array([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]), Buffer.from(jwk.x!, "base64url"), new Uint8Array([0x22, 0x58, 0x20]), Buffer.from(jwk.y!, "base64url"));
    publicKey = Buffer.from(cose).toString("base64");
  });
  test("anonymous and unenrolled users are denied", async () => {
    expect((await call("/api/security/step-up/passkey/options", {}, true)).status).toBe(401);
    expect((await verify({}, true)).status).toBe(401);
    const response = await options(); expect(response.status).toBe(409); expect(await response.json()).toEqual({ error: "등록된 패스키가 없습니다." });
    expect((await (await appMfaChallenge(env, userId, ["passkey"])).json() as any).error).toContain("패스키를 등록하세요");
  });
  test("options restrict credentials, replace challenges, and offer app UI only", async () => {
    await db.prepare('INSERT INTO passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp") VALUES (?, ?, ?, ?, 0, ?, 0)')
      .bind("p1", publicKey, userId, credentialId, "singleDevice").run();
    const first = await options(); expect(first.headers.get("cache-control")).toBe("no-store"); const a = await first.json() as any;
    const b = await (await options()).json() as any;
    expect(a.challenge).not.toBe(b.challenge); expect(b.userVerification).toBe("required"); expect(b.allowCredentials.map((x: any) => x.id)).toEqual([credentialId]);
    const app = await (await appMfaChallenge(env, userId, ["passkey"])).json() as any;
    expect(app.methods).toEqual(["passkey"]); expect(app.ui.methods[0].key).toBe("passkey");
    expect(await usableSecondFactors(env, userId)).not.toContain("passkey");
    expect((await verify(await assertion(a.challenge))).status).toBe(401);
    expect((await verify(await assertion(b.challenge))).status).toBe(401);
  });
  test("expiry, UV, and session binding fail closed", async () => {
    let o = await (await options()).json() as any;
    await db.prepare('UPDATE step_up_passkey_challenges SET expires_at = ? WHERE session_token = ?').bind(new Date(0).toISOString(), token).run();
    expect((await verify(await assertion(o.challenge))).status).toBe(401);
    o = await (await options()).json() as any;
    await db.prepare('UPDATE step_up_passkey_challenges SET session_token = ? WHERE session_token = ?').bind("another-session", token).run();
    expect((await verify(await assertion(o.challenge))).status).toBe(401);
    o = await (await options()).json() as any;
    expect((await verify(await assertion(o.challenge, 1))).status).toBe(401);
  });
  test("another user's credential is neither offered nor accepted", async () => {
    const created = await call("/api/admin/users", { email: "other@passkey.test", name: "Other", sendEmail: false });
    expect(created.status).toBe(201);
    const otherId = ((await created.json()) as any).user.id;
    const otherCredential = b64url(crypto.getRandomValues(new Uint8Array(32)));
    await db.prepare('INSERT INTO passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp") VALUES (?, ?, ?, ?, 0, ?, 0)')
      .bind("other-passkey", publicKey, otherId, otherCredential, "singleDevice").run();
    const o = await (await options()).json() as any;
    expect(o.allowCredentials.map((item: any) => item.id)).toEqual([credentialId]);
    const foreign = await assertion(o.challenge);
    foreign.id = otherCredential; foreign.rawId = otherCredential;
    expect((await verify(foreign)).status).toBe(401);
  });
  test("a real signed UV assertion records the proof but does not satisfy a risk challenge", async () => {
    await openStepUpChallenge({ env, sessionToken: token, userId, reasons: ["risk"], requestPath: "/test" });
    const o = await (await options()).json() as any;
    const body = await assertion(o.challenge);
    const result = await verify(body); expect(result.status).toBe(200); expect(await result.json()).toEqual({ verified: true });
    expect((await db.prepare('SELECT methods FROM session_mfa_proofs WHERE session_token = ?').bind(token).first<{ methods: string }>())?.methods).toContain("passkey");
    expect((await getStepUpChallenge(env, token)).state).toBe("pending");
    expect((await verify(body)).status).toBe(401);
  });
  test("per-user route limits preserve the challenge and reset after the window", async () => {
    const second = await createAuth(env).api.createUser({ body: {
      email: "rate-other@passkey.test", name: "Rate Other", password: "SelfSvc-7d9Kpw9zL2xQ",
      role: "user", data: { username: "rateother", emailVerified: true },
    } });
    const otherJar = new Map<string, string>();
    expect((await call("/api/auth/sign-in/username", { username: "rateother", password: "SelfSvc-7d9Kpw9zL2xQ" }, false, otherJar)).status).toBe(200);
    await db.prepare('INSERT INTO passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp") VALUES (?, ?, ?, ?, 0, ?, 0)')
      .bind("rate-other-key", publicKey, second.user.id, b64url(crypto.getRandomValues(new Uint8Array(32))), "singleDevice").run();
    await db.prepare("DELETE FROM fingerprint_lookup_limits WHERE budget_key LIKE 'passkey_step_up:%'").run();
    const baseTime = Date.now();
    const clock = spyOn(Date, "now").mockReturnValue(baseTime);
    try {
      // Freeze the clock so the ten requests cannot straddle a minute boundary.
      let challenge = "";
      for (let i = 0; i < 10; i++) {
        const response = await options();
        expect(response.status).toBe(200);
        challenge = ((await response.json()) as any).challenge;
      }
      const blockedOptions = await options();
      expect(blockedOptions.status).toBe(429);
      expect(await blockedOptions.json()).toEqual({ error: "잠시 뒤에 다시 시도하세요." });
      expect(Number(blockedOptions.headers.get("retry-after"))).toBeGreaterThan(0);
      expect(blockedOptions.headers.get("cache-control")).toBe("no-store");
      expect((await db.prepare("SELECT challenge FROM step_up_passkey_challenges WHERE session_token = ?").bind(token).first<{ challenge: string }>())?.challenge).toBe(challenge);
      expect((await call("/api/security/step-up/passkey/options", {}, false, otherJar)).status).toBe(200);

      for (let i = 0; i < 10; i++) expect((await verify({})).status).toBe(401);
      // Install a fresh pending challenge without consuming another options budget.
      await db.prepare("INSERT INTO step_up_passkey_challenges (session_token, user_id, challenge, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(session_token) DO UPDATE SET user_id = excluded.user_id, challenge = excluded.challenge, expires_at = excluded.expires_at")
        .bind(token, userId, challenge, new Date(baseTime + 300_000).toISOString()).run();
      const blockedVerify = await verify({});
      expect(blockedVerify.status).toBe(429);
      expect(await blockedVerify.json()).toEqual({ error: "잠시 뒤에 다시 시도하세요." });
      expect(Number(blockedVerify.headers.get("retry-after"))).toBeGreaterThan(0);
      expect((await db.prepare("SELECT challenge FROM step_up_passkey_challenges WHERE session_token = ?").bind(token).first<{ challenge: string }>())?.challenge).toBe(challenge);
      expect((await call("/api/security/step-up/passkey/verify", {}, false, otherJar)).status).toBe(401);

      clock.mockReturnValue(baseTime + 60_000);
      // The rejected verify did not consume the row; after reset an allowed
      // invalid attempt reaches verification and consumes it.
      const verified = await verify({});
      expect(verified.status).toBe(401);
      expect(await db.prepare("SELECT challenge FROM step_up_passkey_challenges WHERE session_token = ?").bind(token).first()).toBeNull();
      expect((await options()).status).toBe(200);
    } finally {
      clock.mockRestore();
    }
  });
});
