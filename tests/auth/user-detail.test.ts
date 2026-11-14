import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** The administrator's detail view of one user. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Detail-7d9Kpw9zL2xQ";

describe("user detail", () => {
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

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@detail.test", name: "Admin", username: "detadmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "detadmin", password: PASSWORD } })).status).toBe(200);
  });

  test("summary, groups and the apps a user can open and why", async () => {
    const detail = await json(await call(`/api/admin/users/${adminId}/detail`));
    expect(detail.user).toMatchObject({ email: "admin@detail.test", roles: ["admin"], active: true, twoFactorEnabled: false });

    const sales = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "sales", description: "" } }))).group;
    const ops = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "ops", description: "" } }))).group;
    await call(`/api/admin/directory-groups/${sales.id}/members`, { method: "POST", body: { userId: adminId } });
    expect((await json(await call(`/api/admin/users/${adminId}/groups`))).groups.map((g: any) => g.name)).toEqual(["sales"]);

    for (const [slug, groups] of [["open", null], ["for-sales", [sales.id]], ["for-ops", [ops.id]]] as const) {
      await call("/api/admin/applications", { method: "POST", body: { slug, name: slug, protocol: "bookmark", launchUrl: "https://x.example.com" } });
      if (groups) await call(`/api/admin/applications/${slug}/assignment`, { method: "PUT", body: { mode: "groups", groups } });
    }
    const apps = (await json(await call(`/api/admin/users/${adminId}/applications`))).applications;
    const by = (slug: string) => apps.find((a: any) => a.slug === slug);
    expect(by("open")).toMatchObject({ access: "everyone" });
    expect(by("for-sales")).toMatchObject({ access: "group", via: ["sales"] });
    expect(by("for-ops")).toMatchObject({ access: "none" });
  });

  test("the profile keeps administrator fields and the phone number, and refuses bad values", async () => {
    const put = (body: unknown) => call(`/api/admin/users/${adminId}/profile`, { method: "PUT", body });
    expect((await put({ phoneNumber: "010-1234-5678" })).status).toBe(400);
    expect((await put({ fields: { nope: "x" } })).status).toBe(400);
    expect((await put({ fields: { secondEmail: "not-an-email" } })).status).toBe(400);
    expect((await put({ name: "Admin Kim", phoneNumber: "01012345678", fields: { title: "CTO", department: "Platform" } })).status).toBe(200);
    const profile = await json(await call(`/api/admin/users/${adminId}/profile`));
    expect(profile).toMatchObject({ name: "Admin Kim", phoneNumber: "01012345678", fields: { title: "CTO", department: "Platform" } });
    // The number is not verified until the user proves it: it must not receive codes yet.
    expect((await json(await call(`/api/admin/users/${adminId}/detail`))).user).toMatchObject({ phoneNumber: "01012345678", phoneVerified: false });
    // Clearing a field removes it.
    await put({ fields: { department: "" } });
    expect((await json(await call(`/api/admin/users/${adminId}/profile`))).fields).toEqual({ title: "CTO" });
  });

  test("devices come from the sign-in history, authenticators from the stored factors, logs from the audit trail", async () => {
    await db.prepare(
      `INSERT INTO login_history (id, user_id, occurred_at, ip, user_agent, country, region, city, method)
       VALUES ('l1', ?, ?, '203.0.113.9', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36', 'KR', 'Incheon', 'Incheon', 'password')`,
    ).bind(adminId, new Date().toISOString()).run();
    const devices = await json(await call(`/api/admin/users/${adminId}/devices`));
    expect(devices.devices[0]).toMatchObject({ label: "Mac OS X Chrome", location: "Incheon, Incheon, KR", count: 1 });
    expect(devices.logins[0]).toMatchObject({ device: "Mac OS X Chrome", method: "password", reported: false });
    expect(devices.sessions.length).toBeGreaterThan(0);

    const auth = await json(await call(`/api/admin/users/${adminId}/authenticators`));
    expect(auth).toMatchObject({ password: { set: false }, passkeys: [], totp: false, hardwareTokens: [] });

    const logs = await json(await call(`/api/admin/audit-events?userId=${adminId}&limit=20`));
    expect(logs.events.length).toBeGreaterThan(0);
    expect(logs.events.every((e: any) => e.actor_user_id === adminId || e.target_user_id === adminId)).toBe(true);
  });

  test("the log is read by page with a total, by family of event and by text, with names", async () => {
    const first = await json(await call("/api/admin/audit-events?page=1&limit=2"));
    expect(first.events).toHaveLength(2);
    expect(first.total).toBeGreaterThan(2);
    expect(first.page).toBe(1);
    const second = await json(await call("/api/admin/audit-events?page=2&limit=2"));
    expect(second.events.map((e: any) => e.id)).not.toContain(first.events[0].id);
    expect(second.events[0].id).not.toBe(first.events[1].id);

    const family = await json(await call("/api/admin/audit-events?page=1&limit=50&eventPrefix=identity."));
    expect(family.events.length).toBeGreaterThan(0);
    expect(family.events.every((e: any) => e.event_type.startsWith("identity."))).toBe(true);
    expect(family.total).toBeLessThan(first.total);

    const text = await json(await call("/api/admin/audit-events?page=1&q=profile"));
    expect(text.events.length).toBeGreaterThan(0);
    expect(text.events.every((e: any) => `${e.event_type}${e.request_path}`.includes("profile"))).toBe(true);
    const named = family.events.find((e: any) => e.actor_user_id === adminId);
    expect(named.actor).toMatchObject({ email: "admin@detail.test" });

    expect((await call("/api/admin/audit-events?page=0")).status).toBe(400);
    expect((await call("/api/admin/audit-events?eventPrefix=a%25b")).status).toBe(400);
  });

  test("only administrators can read it", async () => {
    jar.clear();
    expect((await call(`/api/admin/users/${adminId}/detail`)).status).toBe(401);
    expect((await call("/api/admin/users/nobody/profile")).status).toBe(401);
  });
});
