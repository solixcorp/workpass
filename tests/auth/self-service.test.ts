import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** Notifications, the person's own page, suspicious reports and the overview. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "SelfSvc-7d9Kpw9zL2xQ";

describe("self service and overview", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "detail-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string> }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET" && !headers.Origin) headers.Origin = ORIGIN;
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

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@self.test", name: "Admin", username: "selfadmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "selfadmin", password: PASSWORD } })).status).toBe(200);
  });

  test("people who gain an app are told, and read their notifications", async () => {
    const created = await json(await call("/api/admin/users", { method: "POST", body: { email: "ana@self.test", name: "Ana", sendEmail: false } }));
    const anaId = created.user.id as string;
    const group = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "design", description: "" } }))).group;
    await call(`/api/admin/directory-groups/${group.id}/members`, { method: "POST", body: { userId: anaId } });
    await call("/api/admin/applications", { method: "POST", body: { slug: "figma", name: "Figma", protocol: "bookmark", launchUrl: "https://figma.example.com" } });
    // A switched-off app tells nobody; switching it on tells the people it is for.
    await call("/api/admin/applications/figma/assignment", { method: "PUT", body: { mode: "groups", groups: [group.id] } });
    expect((await db.prepare("SELECT COUNT(*) AS n FROM user_notifications").first<{ n: number }>())!.n).toBe(0);
    expect((await call("/api/admin/applications/figma/enable", { method: "POST", body: {} })).status).toBe(200);
    const told = await db.prepare("SELECT title, body FROM user_notifications WHERE user_id = ?").bind(anaId).all<{ title: string; body: string }>();
    expect(told.results).toEqual([{ title: "새 앱을 사용할 수 있습니다", body: "Figma을(를) 이제 열 수 있습니다." }]);
    // Someone outside the group is not told.
    const others = await db.prepare("SELECT COUNT(*) AS n FROM user_notifications WHERE user_id != ?").bind(anaId).first<{ n: number }>();
    expect(others!.n).toBe(0);

    await db.prepare("INSERT INTO user_notifications (id, user_id, kind, title, body, created_at) VALUES ('n1', ?, 'x', 'Hello', 'Body', ?)").bind(adminId, new Date().toISOString()).run();
    const list = await json(await call("/api/me/notifications"));
    expect(list).toMatchObject({ unread: 1, notifications: [{ id: "n1", title: "Hello", readAt: null }] });
    await call("/api/me/notifications/read", { method: "POST", body: {} });
    expect((await json(await call("/api/me/notifications"))).unread).toBe(0);
  });

  test("a person edits their own name and phone number, not the administrator fields", async () => {
    expect((await call("/api/me/profile", { method: "PUT", body: { phoneNumber: "010" } })).status).toBe(400);
    expect((await call("/api/me/profile", { method: "PUT", body: { name: "Admin Self", phoneNumber: "+821099998888" } })).status).toBe(200);
    expect(await json(await call("/api/me/profile"))).toMatchObject({ name: "Admin Self", phoneNumber: "+821099998888", phoneVerified: false });
    // A cross-origin write is refused.
    const refused = await call("/api/me/profile", { method: "PUT", body: { name: "x" }, headers: { Origin: "https://evil.example" } });
    expect(refused.status).toBe(403);
  });

  test("recent activity groups sign-ins by device and a report reaches the administrators once", async () => {
    const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";
    for (const id of ["a", "b"]) {
      await db.prepare("INSERT INTO login_history (id, user_id, occurred_at, ip, user_agent, country, city, method) VALUES (?, ?, ?, '198.51.100.7', ?, 'KR', 'Seoul', 'password')")
        .bind(id, adminId, new Date().toISOString(), ua).run();
    }
    const activity = await json(await call("/api/me/activity"));
    expect(activity.logins[0]).toMatchObject({ device: "Windows Chrome", location: "Seoul, KR", count: 2, reported: false });

    const loginId = activity.logins[0].loginId as string;
    expect((await call("/api/me/suspicious-reports", { method: "POST", body: { loginId: "nope" } })).status).toBe(404);
    const made = await call("/api/me/suspicious-reports", { method: "POST", body: { loginId, summary: "내가 아님" } });
    expect(made.status).toBe(201);
    expect((await call("/api/me/suspicious-reports", { method: "POST", body: { loginId } })).status).toBe(409);
    const told = await db.prepare("SELECT title FROM user_notifications WHERE kind = 'suspicious_report'").all<{ title: string }>();
    expect(told.results.length).toBe(1);

    const reports = await json(await call("/api/admin/suspicious-reports"));
    expect(reports.reports).toHaveLength(1);
    expect(reports.reports[0]).toMatchObject({ email: "admin@self.test", status: "open" });
    expect((await call(`/api/admin/suspicious-reports/${reports.reports[0].id}/close`, { method: "POST", body: {} })).status).toBe(200);
    expect((await json(await call("/api/admin/suspicious-reports"))).reports).toHaveLength(0);
  });

  test("asking for an app needs a message and reaches the administrators", async () => {
    expect((await call("/api/me/app-requests", { method: "POST", body: { slug: "figma", message: " " } })).status).toBe(400);
    expect((await call("/api/me/app-requests", { method: "POST", body: { slug: "missing", message: "please" } })).status).toBe(404);
    expect((await call("/api/me/app-requests", { method: "POST", body: { slug: "figma", message: "디자인 작업에 필요합니다" } })).status).toBe(201);
    const told = await db.prepare("SELECT title, body FROM user_notifications WHERE kind = 'app_request'").all<{ title: string; body: string }>();
    expect(told.results[0]).toMatchObject({ title: "앱 접근 요청: Figma" });
    expect(told.results[0]!.body).toContain("디자인 작업에 필요합니다");
    // Without an app, the message still goes out.
    expect((await call("/api/me/app-requests", { method: "POST", body: { message: "회계 도구가 필요해요" } })).status).toBe(201);
  });

  test("the overview counts, lists things to do and the security signals", async () => {
    await db.prepare("INSERT INTO suspicious_reports (id, user_id, summary, created_at) VALUES ('r9', ?, 's', ?)").bind(adminId, new Date().toISOString()).run();
    const overview = await json(await call("/api/admin/overview"));
    expect(overview.counts).toMatchObject({ users: 2, groups: 1 });
    expect(overview.counts.apps).toBeGreaterThanOrEqual(1);
    expect(overview.tasks.map((t: any) => t.id)).toContain("reports");
    expect(overview.tasks.find((t: any) => t.id === "passwords")?.count).toBeGreaterThanOrEqual(1);
    expect(overview.changes.length).toBeGreaterThan(0);
    expect(overview.security.windowDays).toBe(30);
    expect(overview.services.map((s: any) => s.name)).toContain("기기 위험 판정");
  });

  test("none of it is open without a session", async () => {
    jar.clear();
    for (const path of ["/api/me/notifications", "/api/me/profile", "/api/me/activity", "/api/admin/overview", "/api/admin/suspicious-reports"]) {
      expect((await call(path)).status).toBe(401);
    }
  });
});
