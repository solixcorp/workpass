import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** An administrator reads what a user allowed, when, and the device verdict at that moment. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Activity-7d9Kpw9zL2";
const CALLBACK = "https://wiki.example.com/callback";

describe("phone number verification", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", MFA_SMS_WEBHOOK_URL: "https://sms.test/send",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";
  let clientId = "";

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
  const json = async (response: Response) => (await response.json()) as any;

  const authorizePath = () => `/api/auth/oauth2/authorize?${new URLSearchParams({
    client_id: clientId, redirect_uri: CALLBACK, response_type: "code", scope: "openid profile email",
    state: "s", code_challenge: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", code_challenge_method: "S256",
  })}`;

  const realFetch = globalThis.fetch;
  const texts: Array<{ to: string; code: string }> = [];
  let smsFails = false;
  const stub = async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input) === "https://sms.test/send") {
      if (smsFails) return new Response("no", { status: 500 });
      texts.push(JSON.parse(String(init?.body)));
      return new Response("{}", { status: 200 });
    }
    return realFetch(input, init);
  };

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@phone.test", name: "Admin", username: "phoneadmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "phoneadmin", password: PASSWORD } })).status).toBe(200);
    globalThis.fetch = stub as typeof fetch;
  });
  afterAll(() => { globalThis.fetch = realFetch; });

  const send = () => call("/api/me/phone/send-code", { method: "POST", body: {} });
  const verify = (code: string) => call("/api/me/phone/verify", { method: "POST", body: { code } });
  const age = (column: string, ms: number) => db.prepare(`UPDATE phone_verifications SET ${column} = ? WHERE user_id = ?`).bind(new Date(Date.now() + ms).toISOString(), adminId).run();

  test("a code needs a saved number, and the person is told what is missing", async () => {
    expect((await send()).status).toBe(409);
    expect((await json(await call("/api/me/profile"))).smsAvailable).toBe(true);
    expect((await call("/api/me/profile", { method: "PUT", body: { phoneNumber: "01077778888" } })).status).toBe(200);
    // Spaces and hyphens are accepted and dropped; foreign numbers are refused.
    expect((await call("/api/me/profile", { method: "PUT", body: { phoneNumber: "010 7777 8888" } })).status).toBe(200);
    expect((await call("/api/me/profile", { method: "PUT", body: { phoneNumber: "+821077778888" } })).status).toBe(400);
    expect((await call("/api/me/profile", { method: "PUT", body: { phoneNumber: "+14155550123" } })).status).toBe(400);
    expect(((await (await call("/api/me/profile")).json()) as { phoneNumber: string }).phoneNumber).toBe("01077778888");
    expect((await json(await call("/api/me/profile"))).phoneVerified).toBe(false);
    expect((await verify("123456")).status).toBe(400); // no code requested yet
  });

  test("the right code verifies the number, the wrong ones are counted and stop", async () => {
    expect((await json(await send()))).toMatchObject({ sent: true, expiresInSeconds: 600 });
    expect(texts).toHaveLength(1);
    expect(texts[0]).toMatchObject({ to: "01077778888" });
    const code = texts[0]!.code;
    expect(code).toMatch(/^[0-9]{6}$/);
    const stored = await db.prepare("SELECT code_hash FROM phone_verifications WHERE user_id = ?").bind(adminId).first<{ code_hash: string }>();
    expect(stored!.code_hash).not.toContain(code);

    const wrong = code === "000000" ? "000001" : "000000";
    const first = await verify(wrong);
    expect(first.status).toBe(400);
    expect(await json(first)).toMatchObject({ reason: "wrong", attemptsLeft: 4 });
    expect((await verify("12ab")).status).toBe(400);
    expect((await json(await call("/api/me/profile"))).phoneVerified).toBe(false);

    expect(await json(await verify(code))).toEqual({ verified: true });
    expect((await json(await call("/api/me/profile"))).phoneVerified).toBe(true);
    // The code is used up, and a verified number is not verified twice.
    expect((await verify(code)).status).toBe(400);
    expect((await send()).status).toBe(409);
    const told = await db.prepare("SELECT title FROM user_notifications WHERE kind = 'phone_verified'").all<{ title: string }>();
    expect(told.results).toHaveLength(1);
  });

  test("changing the number cancels the code and clears the verified flag", async () => {
    expect((await call("/api/me/profile", { method: "PUT", body: { phoneNumber: "01099990000" } })).status).toBe(200);
    expect((await json(await call("/api/me/profile"))).phoneVerified).toBe(false);
    await send();
    const code = texts.at(-1)!.code;
    expect(texts.at(-1)!.to).toBe("01099990000");
    // A code sent to one number cannot confirm another.
    expect((await call("/api/me/profile", { method: "PUT", body: { phoneNumber: "01011112222" } })).status).toBe(200);
    expect((await json(await verify(code))).reason).toBe("no_code");
    expect((await json(await call("/api/me/profile"))).phoneVerified).toBe(false);
  });

  test("codes are throttled, expire, and five wrong tries use one up", async () => {
    texts.length = 0;
    expect((await send()).status).toBe(200);
    const soon = await send();
    expect(soon.status).toBe(429);
    expect((await json(soon)).reason).toBe("too_soon");

    await age("sent_at", -61_000);
    expect((await send()).status).toBe(200);
    let code = texts.at(-1)!.code;
    await age("expires_at", -1_000);
    expect((await json(await verify(code))).reason).toBe("expired");

    await age("sent_at", -61_000).catch(() => null);
    await db.prepare("DELETE FROM phone_verifications WHERE user_id = ?").bind(adminId).run();
    expect((await send()).status).toBe(200);
    code = texts.at(-1)!.code;
    const wrong = code === "111111" ? "222222" : "111111";
    for (let i = 0; i < 4; i += 1) expect((await verify(wrong)).status).toBe(400);
    expect((await json(await verify(wrong))).reason).toBe("too_many_attempts");
    // Even the right code no longer works: the guesses were used up.
    expect((await json(await verify(code))).reason).toBe("no_code");
  });

  test("an hour allows only a few codes, and a gateway failure leaves no code behind", async () => {
    await db.prepare("DELETE FROM phone_verifications WHERE user_id = ?").bind(adminId).run();
    smsFails = true;
    const failed = await send();
    expect(failed.status).toBe(502);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM phone_verifications").first<{ n: number }>())!.n).toBe(0);
    smsFails = false;

    for (let i = 0; i < 5; i += 1) {
      await age("sent_at", -61_000).catch(() => null);
      expect((await send()).status).toBe(200);
    }
    await age("sent_at", -61_000);
    const capped = await send();
    expect(capped.status).toBe(429);
    expect((await json(capped)).reason).toBe("too_many");
  });

  test("a text message is never a way to sign in", async () => {
    for (const [method, path] of [["POST", "/api/auth/phone-number/send-otp"], ["POST", "/api/auth/phone-number/verify"], ["POST", "/api/auth/sign-in/phone-number"], ["POST", "/api/auth/phone-number/reset-password"]] as const) {
      expect((await call(path, { method, body: { phoneNumber: "01011112222", code: "123456" } })).status).toBe(404);
    }
    jar.clear();
    expect((await call("/api/auth/phone-number/verify", { method: "POST", body: { phoneNumber: "01011112222", code: "123456" } })).status).toBe(404);
    expect((await send()).status).toBe(401);
    expect((await verify("123456")).status).toBe(401);
  });
});
