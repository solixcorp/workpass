import { expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import { alertMessages, alertRiskyLogin, describeAttempt, isBlockingRisk } from "../../src/security/risky-login-alert";
import { createTestD1 } from "../test-d1";

const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36";

function attempt(cf: Record<string, unknown> | null = { city: "Seoul", country: "KR" }) {
  const request = new Request("https://auth.test/api/opaque/auth/finish", {
    method: "POST", headers: { "cf-connecting-ip": "211.108.12.34", "user-agent": UA },
  });
  if (cf) Object.defineProperty(request, "cf", { value: cf, enumerable: true });
  return request;
}

test("only blocking verdicts trigger an alert", () => {
  expect(isBlockingRisk(["bot_detected", "untrusted_device"])).toBe(true);
  expect(isBlockingRisk(["tor_network_detected"])).toBe(true);
  expect(isBlockingRisk(["untrusted_device", "vpn_detected"])).toBe(false);
  expect(isBlockingRisk([])).toBe(false);
});

test("the message names the full IP, the place and a short device", () => {
  const ctx = describeAttempt(attempt(), new Date("2026-11-14T06:16:00Z"));
  expect(ctx).toEqual({ ip: "211.108.12.34", place: "Seoul, Korea", device: "MacOS, Chrome", when: "2026-11-14 15:16 (KST)" });
  const text = alertMessages({ AUTH_BASE_URL: "https://auth.solixllc.com" } as Env, "a@solix.kr", ["bot_detected"], ctx);
  expect(text.subject).toBe("[Solix] 봇으로 의심되는 로그인 시도를 차단했습니다");
  for (const part of ["211.108.12.34", "Seoul, Korea", "MacOS, Chrome", "https://auth.solixllc.com/security"]) expect(text.email).toContain(part);
  expect(text.sms).toContain("211.108.12.34");
  expect(text.sms).toContain("auth.solixllc.com/security");
  expect(alertMessages({ AUTH_BASE_URL: "https://x.test" } as Env, "a", ["tor_network_detected"], ctx).email).toContain("Tor");
});

test("a missing edge location reads as unknown, and a city is optional", () => {
  expect(describeAttempt(attempt(null)).place).toBe("알 수 없음");
  expect(describeAttempt(attempt({ country: "JP" })).place).toBe("Japan");
});

test("the owner is told once per hour, by mail and in the app, and never for a soft verdict", async () => {
  const { db } = createTestD1();
  const sent: Array<{ to: string; subject: string }> = [];
  const hook = "https://mail.test/hook";
  const env = {
    DB: db, AUTH_SECRET: "alert-secret-0123456789abcdef-0123456789abcdef", AUTH_BASE_URL: "https://auth.test",
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    INVITATION_EMAIL_WEBHOOK_URL: hook, MAIL_FROM: "noreply@auth.test",
  } as unknown as Env;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input) === hook) { const body = JSON.parse(String(init?.body)); sent.push({ to: body.to, subject: body.subject }); return new Response("ok"); }
    return realFetch(input, init);
  }) as typeof fetch;
  try {
    expect((await worker.fetch(new Request("https://auth.test/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } }), env)).status).toBe(200);
    const now = new Date().toISOString();
    await db.prepare('INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt") VALUES (?, ?, ?, 1, ?, ?)').bind("u1", "A", "a@solix.kr", now, now).run();

    await alertRiskyLogin(env, { userId: "u1", request: attempt(), reasons: ["untrusted_device"] });
    expect(sent).toHaveLength(0);

    await alertRiskyLogin(env, { userId: "u1", request: attempt(), reasons: ["bot_detected", "tampering_detected"] });
    expect(sent).toEqual([{ to: "a@solix.kr", subject: "[Solix] 봇으로 의심되는 로그인 시도를 차단했습니다" }]);
    const notice = await db.prepare("SELECT kind, body FROM user_notifications WHERE user_id = 'u1'").first<{ kind: string; body: string }>();
    expect(notice?.kind).toBe("risky_login_blocked");
    expect(notice?.body).toContain("211.108.12.34");

    await alertRiskyLogin(env, { userId: "u1", request: attempt(), reasons: ["bot_detected"] });
    expect(sent).toHaveLength(1);
    await alertRiskyLogin(env, { userId: "missing", request: attempt(), reasons: ["bot_detected"] });
    expect(sent).toHaveLength(1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("the message says 'detected' rather than 'blocked' when sign-in was allowed", () => {
  const ctx = describeAttempt(attempt(), new Date("2026-11-14T06:16:00Z"));
  const open = alertMessages({ AUTH_BASE_URL: "https://auth.test" } as Env, "a@solix.kr", ["bot_detected"], ctx, false);
  expect(open.subject).toBe("[Solix] 봇으로 의심되는 로그인 시도를 감지했습니다");
  expect(open.email).toContain("로그인은 막지 않았습니다");
  expect(open.email).not.toContain("계정에는 접속되지 않았습니다");
  expect(open.sms).toContain("로그인 감지");
});
