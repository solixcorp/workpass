import { describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** The activation link is mailed through the shared transactional sender. */
describe("activation link delivery", () => {
  const { db } = createTestD1();
  const sent: Array<Record<string, unknown>> = [];
  const env = {
    DB: db, AUTH_SECRET: "activation-mail-secret-0123456789abcdef-01", AUTH_BASE_URL: "http://127.0.0.1:8787",
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", INVITATION_EMAIL_WEBHOOK_URL: "https://mail.test/hook",
    INVITATION_EMAIL_FROM: "no-reply@solixcorp.test",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(3))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  const real = globalThis.fetch;

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string> }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = env.AUTH_BASE_URL;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await mod.fetch(new Request(`${env.AUTH_BASE_URL}${path}`, {
      method: init?.method ?? "GET", headers, body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return response;
  }

  test("mails the link instead of showing it, and reports a delivery failure", async () => {
    await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@mail.test", name: "Admin", username: "mailadmin", password: "MailOnly-7d9Kpw9zL2" },
    });
    await call("/api/auth/sign-in/username", { method: "POST", body: { username: "mailadmin", password: "MailOnly-7d9Kpw9zL2" } });

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).startsWith("https://mail.test/")) {
        sent.push(JSON.parse(String(init?.body)));
        return new Response("ok");
      }
      return real(input, init);
    }) as typeof fetch;
    try {
      const ok = await (await call("/api/admin/users", { method: "POST", body: { email: "mailed@mail.test", name: "Mailed User" } })).json() as any;
      expect(ok.activation).toMatchObject({ emailed: true, activationUrl: null });
      expect(sent).toHaveLength(1);
      expect(sent[0]!.to).toBe("mailed@mail.test");
      expect(String(sent[0]!.text)).toContain("http://127.0.0.1:8787/activate#");
      const delivered = await db.prepare("SELECT delivered_to, delivered_at FROM account_activation_tokens WHERE delivered_to IS NOT NULL").first<Record<string, string>>();
      expect(delivered?.delivered_to).toBe("mailed@mail.test");
      expect(delivered?.delivered_at).toBeTruthy();

      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) =>
        String(input).startsWith("https://mail.test/") ? new Response("nope", { status: 500 }) : real(input, init)) as typeof fetch;
      const failed = await (await call("/api/admin/users", { method: "POST", body: { email: "unmailed@mail.test", name: "Unmailed" } })).json() as any;
      // A failed send falls back to showing the link once, flagged as an error.
      expect(failed.activation.emailed).toBeFalse();
      expect(failed.activation.emailError).toBeTrue();
      expect(failed.activation.activationUrl).toContain("/activate#");
    } finally {
      globalThis.fetch = real;
    }
  });
});
