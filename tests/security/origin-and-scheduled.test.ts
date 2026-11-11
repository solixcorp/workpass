import { describe, expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

const origin = "http://127.0.0.1:8787";
const execution = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

describe("security route origins", () => {
  test("mutations reject a foreign origin and accept the configured origin with a session", async () => {
    const { db } = createTestD1();
    const env = { DB: db, AUTH_BASE_URL: origin, AUTH_SECRET: "origin-test-secret-0123456789abcdef0123456789",
      ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
      ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
      ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true" } as unknown as Env;
    let cookie = "";
    const call = async (path: string, method: string, body?: unknown, headers: Record<string, string> = {}) => {
      const response = await worker.fetch(new Request(origin + path, {
        method, headers: { Origin: origin, "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}), ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      }), env, execution);
      const setCookies = response.headers.getSetCookie();
      if (setCookies.length) cookie = setCookies.map((value) => value.split(";")[0]).join("; ");
      return response;
    };
    await call("/_internal/migrate", "POST", undefined, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` });
    const password = "Security-7d9Kpw9zL2xQ";
    const bootstrap = await call("/api/admin/bootstrap", "POST", { email: "admin@origin.test", name: "Admin", username: "originadmin", password }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` });
    expect(bootstrap.status).toBe(201);
    const id = ((await bootstrap.json()) as { user: { id: string } }).user.id;
    expect((await call("/api/auth/sign-in/username", "POST", { username: "originadmin", password })).status).toBe(200);
    const routes = [
      ["POST", "/api/security/trusted-devices", { event_id: "event", password }],
      ["DELETE", "/api/security/trusted-devices", { password }],
      ["DELETE", "/api/security/trusted-devices/device", { password }],
      ["DELETE", `/api/security/trusted-devices/user/${id}`, undefined],
      ["POST", "/api/security/account-lockdown", { reason: "test" }],
    ] as const;
    for (const [method, path, body] of routes) {
      const wrong = await call(path, method, body, { Origin: "https://evil.test" });
      expect(wrong.status).toBe(403);
      expect(await wrong.json()).toEqual({ error: "Invalid origin" });
    }
    // Enrollment proceeds to the disabled-risk policy; the other operations succeed.
    expect((await call(routes[0][1], routes[0][0], routes[0][2])).status).toBe(404);
    for (const [method, path, body] of routes.slice(1)) {
      expect((await call(path, method, body)).status).toBe(200);
    }
  });
});

describe("scheduled jobs", () => {
  test("continues after the first job fails and dispatches using stored delivery settings", async () => {
    const queries: string[] = [];
    const db = {
      prepare(sql: string) {
        queries.push(sql);
        if (sql.includes("FROM sqlite_master")) throw new TypeError("secret must not be logged");
        const statement = {
          bind: (..._args: unknown[]) => statement,
          all: async () => ({ results: sql.includes("FROM delivery_settings") ? [{ kind: "email", provider: "resend", config: JSON.stringify({ from: "saved@example.com", apiKey: "stored-key" }), secrets: "", updatedBy: "admin", updatedAt: "now" }] :
            sql.includes("FROM pending_event_notifications n") ? [{ id: "pending", event_id: "event", transports: '[{"kind":"email","to":"recipient@example.com"}]', event_type: "test", occurred_at: "2026-01-01" }] : [] }),
          first: async () => null,
          run: async () => ({ meta: { changes: 1 } }),
        };
        return statement;
      },
      batch: async () => [],
    } as unknown as D1Database;
    const originalFetch = globalThis.fetch;
    const originalError = console.error;
    const errors: unknown[][] = [];
    let requestBody = "";
    let authorization = "";
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      requestBody = String(init?.body ?? "");
      authorization = new Headers(init?.headers).get("authorization") ?? "";
      return Response.json({ id: "sent" });
    }) as typeof fetch;
    console.error = (...args: unknown[]) => { errors.push(args); };
    try {
      await worker.scheduled({ scheduledTime: Date.now(), cron: "* * * * *" } as ScheduledController,
        { DB: db, AUTH_BASE_URL: origin } as Env, execution);
    } finally {
      globalThis.fetch = originalFetch;
      console.error = originalError;
    }
    expect(errors).toContainEqual(["Scheduled job failed", { job: "cleanupFingerprintData", name: "TypeError" }]);
    expect(JSON.stringify(errors)).not.toContain("secret must not be logged");
    expect(queries.some((sql) => sql.includes("FROM pending_event_notifications n"))).toBe(true);
    expect(requestBody).toContain("saved@example.com");
    expect(authorization).toBe("Bearer stored-key");
    expect(queries.some((sql) => sql.includes("DELETE FROM pending_event_notifications"))).toBe(true);
  });
});
