import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Activity-7d9Kpw9zL2xQ";
const UA_A = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";
const UA_B = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15";
const UA_OLD = "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0";

describe("current device in recent activity", () => {
  const { db, sqlite } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  let userId = "";
  let cookieA = "";
  let cookieB = "";

  async function call(path: string, options: { method?: string; body?: unknown; headers?: Record<string, string> } = {}) {
    const headers: Record<string, string> = { ...options.headers };
    if (options.method && options.method !== "GET") headers.Origin = ORIGIN;
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    return mod.fetch(new Request(`${ORIGIN}${path}`, {
      method: options.method ?? "GET", headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
  }

  async function signIn(userAgent: string): Promise<string> {
    const response = await call("/api/auth/sign-in/username", {
      method: "POST", headers: { "User-Agent": userAgent }, body: { username: "activityadmin", password: PASSWORD },
    });
    expect(response.status).toBe(200);
    const cookie = response.headers.getSetCookie().find((value) => value.split("=", 1)[0]!.endsWith("session_token"));
    expect(cookie).toBeDefined();
    return cookie!.split(";", 1)[0]!;
  }

  beforeAll(async () => {
    // Exercise the additive migration on a pre-existing table too.
    sqlite.exec("CREATE TABLE login_history (id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL, occurred_at TEXT NOT NULL, ip TEXT, user_agent TEXT, country TEXT, region TEXT, city TEXT, method TEXT)");
    const migration = { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } };
    expect((await call("/_internal/migrate", migration)).status).toBe(200);
    expect((await call("/_internal/migrate", migration)).status).toBe(200);
    const bootstrap = await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@activity.test", name: "Admin", username: "activityadmin", password: PASSWORD },
    });
    expect(bootstrap.status).toBe(201);
    userId = ((await bootstrap.json()) as any).user.id;
    cookieA = await signIn(UA_A);
    cookieB = await signIn(UA_B);
    // A newer unlinked row in A's group must not mask the older matching row.
    for (const [id, ua] of [["legacy-a", UA_A], ["legacy-only", UA_OLD]]) {
      await db.prepare("INSERT INTO login_history (id, user_id, occurred_at, user_agent, method) VALUES (?, ?, ?, ?, 'password')")
        .bind(id, userId, "9999-01-01T00:00:00.000Z", ua).run();
    }
  });

  test("marks only the matching device for each session, including older rows in a group", async () => {
    for (const [cookie, expected, other] of [[cookieA, "Windows Chrome", "Mac OS X Safari"], [cookieB, "Mac OS X Safari", "Windows Chrome"]]) {
      const response = await call("/api/me/activity", { headers: { Cookie: cookie! } });
      expect(response.status).toBe(200);
      const { logins } = await response.json() as { logins: Array<{ device: string; current: boolean; loginId: string }> };
      expect(logins.filter((login) => login.current).map((login) => login.device)).toEqual([expected]);
      expect(logins.find((login) => login.device === other)?.current).toBe(false);
      expect(logins.find((login) => login.loginId === "legacy-only")?.current).toBe(false);
      expect(logins.find((login) => login.device === "Windows Chrome")?.loginId).toBe("legacy-a");
    }
  });

  test("stores only SHA-256 session hashes", async () => {
    for (const cookie of [cookieA, cookieB]) {
      const token = decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1)).split(".")[0]!;
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
      const expected = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
      const row = await db.prepare("SELECT session_token_hash AS hash FROM login_history WHERE user_id = ? AND session_token_hash = ?").bind(userId, expected).first<{ hash: string }>();
      expect(row?.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(row?.hash).not.toBe(token);
    }
    const legacy = await db.prepare("SELECT session_token_hash AS hash FROM login_history WHERE id = 'legacy-only'").first<{ hash: string | null }>();
    expect(legacy?.hash).toBeNull();
  });

  test("requires a session", async () => {
    expect((await call("/api/me/activity")).status).toBe(401);
  });
});
