import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { insertAuditEvent, verifyAuditEventChain } from "../../src/audit/store";
import { createTestD1 } from "../test-d1";

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "SelfSvc-7d9Kpw9zL2xQ";
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36";

describe("my activity event details", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "detail-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let userId = "";
  let otherId = "";

  async function call(path: string, init: { method?: string; body?: unknown; headers?: Record<string, string>; cf?: Record<string, unknown>; anonymous?: boolean } = {}) {
    const headers: Record<string, string> = { ...init.headers };
    if (jar.size && !init.anonymous) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    const request = new Request(`${ORIGIN}${path}`, { method: init.method ?? "GET", headers, body: init.body === undefined ? undefined : JSON.stringify(init.body) });
    if (init.cf) Object.defineProperty(request, "cf", { value: init.cf });
    const response = await mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    if (!init.anonymous) for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i > 0) { if (pair.slice(i + 1)) jar.set(pair.slice(0, i), pair.slice(i + 1)); else jar.delete(pair.slice(0, i)); }
    }
    return response;
  }
  const json = async (response: Response) => await response.json() as any;
  const events = async () => (await json(await call("/api/me/activity"))).events as any[];
  const insert = async (id: string, actor: string | null, type: string, context?: Record<string, unknown>) => insertAuditEvent(env, {
    id, actor_user_id: actor, target_user_id: userId, event_type: type, outcome: "failure", request_path: "/test",
    client_ip: "203.0.113.42", event_context: context,
  });

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    userId = (await json(await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` }, body: { email: "activity@test.example", name: "Self", username: "activityuser", password: PASSWORD } }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "activityuser", password: PASSWORD } })).status).toBe(200);
    otherId = (await json(await call("/api/admin/users", { method: "POST", body: { email: "other@test.example", name: "Other Admin", sendEmail: false } }))).user.id;
  });

  test("captures self request IP, geo and short device in the hashed event", async () => {
    const result = await call("/api/auth/change-password", { method: "POST", body: { currentPassword: "wrong", newPassword: PASSWORD }, headers: { "cf-connecting-ip": "198.51.100.5", "user-agent": UA }, cf: { city: "Seoul", region: "Seoul", country: "KR", asn: 123 } });
    expect(result.ok).toBe(false);
    const event = (await events()).find((e) => e.type === "identity.user.password_change.success_or_failure");
    expect(event).toMatchObject({ actor: "self", actorName: null, byAdministrator: false, ip: "198.51.100.5", place: "Seoul, Seoul, KR", device: "Mac OS X Chrome", detail: null });
    const row = await db.prepare("SELECT event_context FROM audit_events WHERE id = ?").bind(event.id).first<{ event_context: string }>();
    expect(row!.event_context).not.toContain(UA);
    expect((await verifyAuditEventChain(env)).verified).toBe(true);
  });

  test("hides an administrator's network and device from the target", async () => {
    await insert("admin-action", otherId, "mfa.hotp.admin_remove", { geo: { city: "Paris", country: "FR" }, device: "Windows Chrome" });
    expect((await events()).find((e) => e.id === "admin-action")).toMatchObject({ actor: "administrator", actorName: "Other Admin", byAdministrator: true, ip: null, place: null, device: null });
  });

  test("old and system events handle missing context", async () => {
    await insert("old-event", null, "mfa.admin_reset");
    expect((await events()).find((e) => e.id === "old-event")).toMatchObject({ actor: "system", actorName: null, place: null, device: null, detail: null });
  });

  test("only recognized MFA methods are exposed as detail", async () => {
    await insert("method", userId, "mfa.hotp.verify", { method: "hotp", secret: "NEVER-LEAK", label: "actor free text" });
    await insert("unexpected", userId, "mfa.hotp.verify", { method: "NEVER-LEAK", unexpected: "NEVER-LEAK" });
    const list = await events();
    expect(list.find((e) => e.id === "method").detail).toBe("hotp");
    expect(list.find((e) => e.id === "unexpected").detail).toBeNull();
    expect(JSON.stringify(list)).not.toContain("NEVER-LEAK");
    expect(JSON.stringify(list)).not.toContain("actor free text");
  });

  test("requires a session", async () => {
    expect((await call("/api/me/activity", { anonymous: true })).status).toBe(401);
  });
});
