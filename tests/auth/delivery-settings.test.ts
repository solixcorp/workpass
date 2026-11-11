import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** An administrator reads what a user allowed, when, and the device verdict at that moment. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Activity-7d9Kpw9zL2";
const CALLBACK = "https://wiki.example.com/callback";

describe("e-mail and SMS providers", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
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
  let sent: Array<{ url: string; headers: Headers; body: string }> = [];
  let answer: (url: string) => Response = () => new Response("{}", { status: 200 });
  const stub = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    sent.push({ url, headers: new Headers(init?.headers), body: String(init?.body ?? "") });
    return answer(url);
  };

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@delivery.test", name: "Admin", username: "delivadmin", password: PASSWORD },
    });
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "delivadmin", password: PASSWORD } })).status).toBe(200);
    globalThis.fetch = stub as typeof fetch;
  });
  afterAll(() => { globalThis.fetch = realFetch; });

  const put = (kind: string, body: unknown) => call(`/api/admin/delivery/${kind}`, { method: "PUT", body });
  const sendTest = (kind: string, to: string) => call(`/api/admin/delivery/${kind}/test`, { method: "POST", body: { to } });

  test("the catalog lists the providers and nothing is configured to begin with", async () => {
    const view = await json(await call("/api/admin/delivery"));
    expect(view.email.source).toBe("none");
    expect(view.sms.source).toBe("none");
    expect(view.catalog.email.map((p: any) => p.id)).toEqual(["resend", "smtp", "cloudflare", "maileroo", "ses"]);
    expect(view.catalog.sms.map((p: any) => p.id)).toEqual(["solapi", "twilio", "webhook"]);
    expect(view.canStoreSecrets).toBe(true);
  });

  test("values are checked before anything is stored", async () => {
    expect((await put("email", { provider: "nope", values: {}, secrets: {} })).status).toBe(400);
    expect((await put("email", { provider: "resend", values: { from: "not-an-address" }, secrets: { apiKey: "re_secret_key_123" } })).status).toBe(400);
    expect((await put("email", { provider: "resend", values: { from: "no-reply@delivery.test" }, secrets: {} })).status).toBe(400); // the key is required
    expect((await put("email", { provider: "smtp", values: { from: "a@delivery.test", host: "smtp.delivery.test", port: "99999" }, secrets: {} })).status).toBe(400);
    expect((await put("sms", { provider: "webhook", values: { url: "http://insecure.example" }, secrets: {} })).status).toBe(400);
    expect((await put("mail", { provider: "resend", values: {}, secrets: {} })).status).toBe(404);
    expect((await call("/api/admin/delivery")).status).toBe(200);
  });

  test("a saved e-mail provider sends, its key is never shown again, and a blank key keeps it", async () => {
    const saved = await put("email", { provider: "resend", values: { from: "no-reply@delivery.test", fromName: "Solix" }, secrets: { apiKey: "re_secret_key_123" } });
    expect(saved.status).toBe(200);
    const text = await (await call("/api/admin/delivery")).text();
    expect(text).not.toContain("re_secret_key_123");
    const view = JSON.parse(text);
    expect(view.email).toMatchObject({ source: "console", provider: "resend", values: { from: "no-reply@delivery.test" }, secretsSet: { apiKey: true } });
    const stored = await db.prepare("SELECT secrets FROM delivery_settings WHERE kind = 'email'").first<{ secrets: string }>();
    expect(stored!.secrets).not.toContain("re_secret_key_123");

    // Editing the sender without retyping the key keeps the key.
    expect((await put("email", { provider: "resend", values: { from: "alerts@delivery.test" }, secrets: {} })).status).toBe(200);
    sent = [];
    expect(await json(await sendTest("email", "someone@example.com"))).toEqual({ ok: true });
    expect(sent[0]!.url).toBe("https://api.resend.com/emails");
    expect(sent[0]!.headers.get("authorization")).toBe("Bearer re_secret_key_123");
    expect(JSON.parse(sent[0]!.body)).toMatchObject({ from: "alerts@delivery.test", to: ["someone@example.com"] });
    expect((await json(await call("/api/admin/overview"))).services.find((s: any) => s.name === "메일 발송").state).toBe("ok");
  });

  test("a provider's refusal is reported without echoing the key", async () => {
    answer = () => new Response('{"message":"invalid api key re_secret_key_123"}', { status: 401 });
    const result = await json(await sendTest("email", "someone@example.com"));
    expect(result.ok).toBe(false);
    expect(result.error).toContain("401");
    expect(result.error).not.toContain("re_secret_key_123");
    answer = () => new Response("{}", { status: 200 });
  });

  test("SMS goes out through Twilio or Solapi with the right credentials", async () => {
    expect((await put("sms", { provider: "twilio", values: { accountSid: "AC123", from: "+12025550123" }, secrets: { authToken: "tok_abcdef" } })).status).toBe(200);
    sent = [];
    expect(await json(await sendTest("sms", "+821012345678"))).toEqual({ ok: true });
    expect(sent[0]!.url).toBe("https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json");
    expect(sent[0]!.headers.get("authorization")).toBe(`Basic ${btoa("AC123:tok_abcdef")}`);
    const form = new URLSearchParams(sent[0]!.body);
    expect(form.get("To")).toBe("+821012345678");
    expect(form.get("From")).toBe("+12025550123");

    expect((await put("sms", { provider: "solapi", values: { apiKey: "NCSKEY", from: "0212345678" }, secrets: { apiSecret: "solapi_secret" } })).status).toBe(200);
    sent = [];
    expect(await json(await sendTest("sms", "+821012345678"))).toEqual({ ok: true });
    expect(sent[0]!.url).toBe("https://api.solapi.com/messages/v4/send");
    expect(sent[0]!.headers.get("authorization")).toMatch(/^HMAC-SHA256 apiKey=NCSKEY, date=.+, salt=[0-9a-f]{32}, signature=[0-9a-f]{64}$/);
    expect(JSON.parse(sent[0]!.body).message).toMatchObject({ to: "01012345678", from: "0212345678" });
    // Solapi only reaches Korean numbers, and says so.
    expect((await json(await sendTest("sms", "+14155550123"))).ok).toBe(false);
    expect((await sendTest("sms", "010-1234")).status).toBe(400);

    // Switching provider drops the old provider's secrets: they must be given again.
    expect((await put("sms", { provider: "twilio", values: { accountSid: "AC123", from: "+12025550123" }, secrets: {} })).status).toBe(400);
  });

  test("secrets cannot be stored without a sealing key, and reset goes back to the deployment", async () => {
    const key = env.AEAD_SEALING_KEY;
    delete (env as any).AEAD_SEALING_KEY;
    expect((await put("email", { provider: "maileroo", values: { from: "a@delivery.test" }, secrets: { apiKey: "mk_123456" } })).status).toBe(409);
    (env as any).AEAD_SEALING_KEY = key;

    expect((await call("/api/admin/delivery/email", { method: "DELETE" })).status).toBe(200);
    expect((await call("/api/admin/delivery/email", { method: "DELETE" })).status).toBe(404);
    expect((await json(await call("/api/admin/delivery"))).email.source).toBe("none");
    expect((await json(await sendTest("email", "someone@example.com"))).ok).toBe(false);
  });

  test("it is for administrators only", async () => {
    jar.clear();
    expect((await call("/api/admin/delivery")).status).toBe(401);
    expect((await put("email", { provider: "resend", values: {}, secrets: {} })).status).toBe(401);
    expect((await sendTest("email", "a@b.test")).status).toBe(401);
  });
});
