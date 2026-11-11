import { expect, test } from "bun:test";
import worker from "../src/index";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";
import { redeemAccountInvitation } from "../src/accounts/store";
import { ensureApplicationTables } from "../src/db/schema";

test("legacy invitation IDs are backfilled once", async () => {
  const { db: DB } = createTestD1();
  const env = { DB } as unknown as Env;
  await DB.prepare(`CREATE TABLE account_invitations (token TEXT PRIMARY KEY NOT NULL, account_id TEXT NOT NULL,
    role TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT)`).run();
  await DB.prepare("INSERT INTO account_invitations VALUES (?, ?, ?, ?, ?, ?, NULL)")
    .bind("old-token", "old-account", "member", "admin", "2026-01-01", "2026-01-08").run();
  await ensureApplicationTables(env);
  const first = await DB.prepare("SELECT id FROM account_invitations").first<{ id: string }>();
  expect(first?.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  await ensureApplicationTables(env);
  expect(await DB.prepare("SELECT id FROM account_invitations").first()).toEqual(first);
});

test("administrators manage invitation IDs, reissue, delivery and account pages", async () => {
  const { db: DB } = createTestD1();
  const base = "http://127.0.0.1:8787";
  const env = { DB, AUTH_BASE_URL: base, AUTH_SECRET: "integration-secret-0123456789abcdef",
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-012345",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-012345",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", INVITATION_EMAIL_WEBHOOK_URL: "https://mail.example.test/" } as unknown as Env;
  const cookies = new Map<string, string>();
  async function call(path: string, method = "GET", body?: unknown, headers: Record<string, string> = {}) {
    const h: Record<string, string> = { Origin: base, ...headers };
    if (cookies.size) h.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (body !== undefined) h["Content-Type"] = "application/json";
    const response = await worker.fetch(new Request(base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env, {} as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!, at = pair.indexOf("=");
      if (at > 0) cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return response;
  }
  expect((await call("/_internal/migrate", "POST", undefined, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
  expect((await call("/api/admin/bootstrap", "POST", { username: "invadmin", email: "admin@inv.test", name: "Admin", password: "TestOnly-7d9Kpw9zL2" }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` })).status).toBe(201);
  expect((await call("/api/auth/sign-in/username", "POST", { username: "invadmin", password: "TestOnly-7d9Kpw9zL2" })).status).toBe(200);
  const account = (await (await call("/api/admin/accounts", "POST", { name: " team ", description: " info " })).json() as any).account;
  const other = (await (await call("/api/admin/accounts", "POST", { name: "other" })).json() as any).account;
  expect(account.name).toBe("team");
  const path = `/api/admin/accounts/${account.id}/invitations`;
  const created = await call(path, "POST", { role: "admin", ttlDays: 2 });
  expect(created.status).toBe(201);
  const invitation = (await created.json() as any).invitation;
  expect(invitation.id).not.toBe(invitation.token);
  const list = (await (await call(path)).json() as any).invitations;
  expect(list[0]).toMatchObject({ id: invitation.id, status: "pending", expiresAt: invitation.expiresAt });
  expect(list[0].token).toBeUndefined();
  expect((await call(`/api/admin/accounts/${other.id}/invitations/by-id/${invitation.id}`, "DELETE")).status).toBe(404);
  expect((await call(`${path}/by-id/${invitation.id}`, "DELETE", undefined, { Origin: "https://evil.test" })).status).toBe(403);
  expect((await call("/api/accounts/join", "POST", { token: invitation.token }, { Origin: "https://evil.test" })).status).toBe(403);
  const originalFetch = globalThis.fetch;
  let mail: any;
  try {
    globalThis.fetch = (async (_input, init) => { mail = JSON.parse(String(init?.body)); return new Response(null, { status: 204 }); }) as typeof fetch;
    const reissue = await call(`${path}/by-id/${invitation.id}/reissue`, "POST", { deliverTo: "new@example.test" });
    expect(reissue.status).toBe(201);
    const result = await reissue.json() as any;
    expect(result.delivered).toBe(true);
    expect(mail.to).toBe("new@example.test");
    expect(mail.text).toContain(result.invitation.token);
    expect((await redeemAccountInvitation(env, invitation.token, "new-user"))).toEqual({ reason: "invalid_token" });
    expect(await redeemAccountInvitation(env, result.invitation.id, "new-user")).toEqual({ reason: "invalid_token" });
    expect(await redeemAccountInvitation(env, result.invitation.token, "new-user")).toMatchObject({ role: "admin" });
    expect((await call(`${path}/by-id/${result.invitation.id}`, "DELETE")).status).toBe(409);
    expect((await call(`${path}/by-id/${invitation.id}`, "DELETE")).status).toBe(409);
    const rows = (await (await call(path)).json() as any).invitations;
    expect(rows.find((r: any) => r.id === invitation.id).status).toBe("revoked");
    expect(rows.find((r: any) => r.id === result.invitation.id).status).toBe("accepted");
    const emailed = await call(path, "POST", { email: "create@example.test" });
    const issued = await emailed.json() as any;
    expect(issued.delivered).toBe(true);
    expect(mail.text).toContain(issued.invitation.token);
    const legacyDelivery = await call(`${path}/${issued.invitation.token}/deliver`, "POST", { to: "legacy@example.test" });
    expect(legacyDelivery.status).toBe(200);
    expect(mail.to).toBe("legacy@example.test");
  } finally { globalThis.fetch = originalFetch; }
  const expired = (await (await call(path, "POST", {})).json() as any).invitation;
  await DB.prepare("UPDATE account_invitations SET expires_at = ? WHERE id = ?").bind("2000-01-01T00:00:00.000Z", expired.id).run();
  expect((await (await call(path)).json() as any).invitations.find((r: any) => r.id === expired.id).status).toBe("expired");
  expect((await call(`${path}/by-id/${expired.id}`, "DELETE")).status).toBe(200);
  const legacy = (await (await call(path, "POST", {})).json() as any).invitation;
  expect((await call(`${path}/${legacy.token}`, "DELETE")).status).toBe(200);
  expect((await call(`/api/admin/accounts/${account.id}`, "PATCH", { name: " other " })).status).toBe(409);
  expect((await call(`/api/admin/accounts/${account.id}`, "PATCH", { name: " renamed ", description: " text " })).status).toBe(200);
  const page = await (await call("/api/admin/accounts?limit=1")).json() as any;
  expect(page.limit).toBe(1);
  expect(page.nextCursor).toBeTruthy();
});
