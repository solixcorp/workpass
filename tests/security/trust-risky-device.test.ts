import { expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { hashSessionToken } from "../../src/users/login-history";
import { grantEnrollGate } from "../mfa/enroll-gate-helper";

test("a risky device can be trusted only after fresh reverification, and never when tampered", async () => {
  const { db } = createTestD1();
  const origin = "http://127.0.0.1:8787";
  const env = {
    DB: db, AUTH_SECRET: "overview-secret-0123456789abcdef-0123456789abc", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  async function call(path: string, method = "GET", body?: unknown, extra: Record<string, string> = {}) {
    const headers: Record<string, string> = { ...extra };
    if (jar.size) headers.Cookie = [...jar].map(([key, value]) => `${key}=${value}`).join("; ");
    if (method !== "GET") headers.Origin = origin;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await worker.fetch(new Request(origin + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const index = pair.indexOf("=");
      if (index > 0) jar.set(pair.slice(0, index), pair.slice(index + 1));
    }
    return response;
  }
  expect((await call("/_internal/migrate", "POST", undefined, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
  const bootstrap = await call("/api/admin/bootstrap", "POST", {
    email: "admin@overview.test", name: "Admin", username: "overviewadmin", password: "Detail-7d9Kpw9zL2xQ",
  }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` });
  const userId = ((await bootstrap.json()) as { user: { id: string } }).user.id;
  const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0";
  expect((await call("/api/auth/sign-in/username", "POST", {
    username: "overviewadmin", password: "Detail-7d9Kpw9zL2xQ",
  }, { "User-Agent": ua, "CF-Connecting-IP": "192.0.2.10" })).status).toBe(200);
  const now = new Date().toISOString();
  const future = new Date(Date.now() + 86400000).toISOString();
  for (const [id, token] of [["risky-session", "risky-token"], ["tampered-session", "tampered-token"], ["unlinked-session", "unlinked-token"]] as const) {
    await db.prepare('INSERT INTO "session" (id, "expiresAt", token, "createdAt", "updatedAt", "userId", "ipAddress", "userAgent") VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, future, token, now, now, userId, "192.0.2.20", ua).run();
  }
  for (const [id, token, digest] of [["l1", "risky-token", "digest-risky"], ["l2", "tampered-token", "digest-tampered"]] as const) {
    await db.prepare(`INSERT INTO login_history (id, user_id, occurred_at, ip, user_agent, session_token_hash, visitor_digest)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(id, userId, now, "192.0.2.20", ua, await hashSessionToken(token), digest).run();
  }
  await db.prepare(`INSERT INTO auth_device_observations (id, user_id, visitor_digest, occurred_at, risk_action, risk_reasons, signals)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).bind("o1", userId, "digest-risky", now, "step_up", JSON.stringify(["untrusted_device", "vpn_detected"]), "{}").run();
  await db.prepare(`INSERT INTO auth_device_observations (id, user_id, visitor_digest, occurred_at, risk_action, risk_reasons, signals)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).bind("o2", userId, "digest-tampered", now, "deny", JSON.stringify(["tampering_detected"]), "{}").run();

  const overview = async () => ((await (await call("/api/security/sessions/overview")).json()) as { sessions: Array<Record<string, any>> }).sessions;
  expect((await overview()).find((s) => s.id === "risky-session")!.trust).toMatchObject({ level: "review", trusted: false, canTrust: true });
  expect((await overview()).find((s) => s.id === "unlinked-session")!.trust).toMatchObject({ trusted: false, canTrust: false });

  // No fresh password + second check yet.
  const denied = await call("/api/security/trusted-devices/from-session", "POST", { sessionId: "risky-session" });
  expect(denied.status).toBe(403);
  expect(await db.prepare("SELECT COUNT(*) AS n FROM trusted_devices").first<{ n: number }>()).toEqual({ n: 0 });

  await grantEnrollGate(db);
  expect((await call("/api/security/trusted-devices/from-session", "POST", { sessionId: "tampered-session" })).status).toBe(403);
  expect((await call("/api/security/trusted-devices/from-session", "POST", { sessionId: "unlinked-session" })).status).toBe(409);
  expect((await call("/api/security/trusted-devices/from-session", "POST", { sessionId: "nope" })).status).toBe(404);
  expect((await call("/api/security/trusted-devices/from-session", "POST", {})).status).toBe(400);

  const ok = await call("/api/security/trusted-devices/from-session", "POST", { sessionId: "risky-session" });
  expect(ok.status).toBe(201);
  const trusted = await db.prepare("SELECT visitor_digest, revoked_at FROM trusted_devices WHERE user_id = ?").bind(userId).all<{ visitor_digest: string; revoked_at: string | null }>();
  expect(trusted.results).toEqual([{ visitor_digest: "digest-risky", revoked_at: null }]);
  expect((await overview()).find((s) => s.id === "risky-session")!.trust).toMatchObject({ trusted: true, canTrust: false });
  const audit = await db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'authentication.trusted_device.enroll' AND outcome = 'success'").first<{ n: number }>();
  expect(audit!.n).toBe(1);
});
