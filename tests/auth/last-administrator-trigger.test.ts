import { describe, expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

describe("last active administrator database invariant", () => {
  test("racing bans cannot both succeed and a sole administrator cannot be demoted or deleted", async () => {
    const { db } = createTestD1();
    const env = {
      DB: db, AUTH_BASE_URL: "http://127.0.0.1:8787",
      AUTH_SECRET: "last-admin-secret-0123456789abcdef0123456789",
      ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef0123456789",
    } as unknown as Env;
    const migration = await worker.fetch(new Request(`${env.AUTH_BASE_URL}/_internal/migrate`, {
      method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` },
    }), env, {} as ExecutionContext);
    expect(migration.status).toBe(200);
    const now = new Date().toISOString();
    for (const id of ["admin-a", "admin-b"]) {
      await db.prepare('INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role, banned) VALUES (?, ?, ?, 0, ?, ?, ?, 0)')
        .bind(id, id, `${id}@example.test`, now, now, "user, admin").run();
    }
    const attempts = await Promise.allSettled(["admin-a", "admin-b"].map((id) =>
      db.prepare('UPDATE "user" SET banned = 1 WHERE id = ?').bind(id).run()));
    expect(attempts.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((result) => result.status === "rejected")).toHaveLength(1);
    const active = await db.prepare('SELECT id FROM "user" WHERE COALESCE(banned, 0) = 0 AND role LIKE ?').bind("%admin%").all<{ id: string }>();
    expect(active.results).toHaveLength(1);
    const survivor = active.results[0]!.id;
    await expect(db.prepare('UPDATE "user" SET role = ? WHERE id = ?').bind("user", survivor).run()).rejects.toThrow("last administrator");
    await expect(db.prepare('DELETE FROM "user" WHERE id = ?').bind(survivor).run()).rejects.toThrow("last administrator");
  });

  test("concurrent administrator ban requests preserve an active administrator", async () => {
    const { db } = createTestD1();
    const origin = "http://127.0.0.1:8787";
    const password = "Race-7d9Kpw9zL2xQ";
    const env = { DB: db, AUTH_BASE_URL: origin, AUTH_SECRET: "race-admin-secret-0123456789abcdef01234567",
      ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef0123456789",
      ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef0123456789",
      ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true" } as unknown as Env;
    async function post(path: string, body: unknown, cookie = "", authorization = "") {
      return worker.fetch(new Request(origin + path, { method: "POST", headers: {
        Origin: origin, "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}),
        ...(authorization ? { Authorization: `Bearer ${authorization}` } : {}),
      }, body: JSON.stringify(body) }), env, {} as ExecutionContext);
    }
    expect((await post("/_internal/migrate", {}, "", env.MIGRATION_TOKEN)).status).toBe(200);
    const bootstrap = await post("/api/admin/bootstrap", { username: "racea", email: "a@race.test", name: "A", password }, "", env.ADMIN_BOOTSTRAP_TOKEN);
    expect(bootstrap.status).toBe(201);
    const a = ((await bootstrap.json()) as { user: { id: string } }).user.id;
    const login = async (username: string) => {
      const response = await post("/api/auth/sign-in/username", { username, password });
      expect(response.status).toBe(200);
      return response.headers.getSetCookie().map((cookie) => cookie.split(";")[0]).join("; ");
    };
    const cookieA = await login("racea");
    const lockdown = await post("/api/security/account-lockdown", { reason: "test" }, cookieA);
    expect(lockdown.status).toBe(409);
    expect(await lockdown.json()).toEqual({ error: "마지막 관리자는 차단할 수 없습니다." });
    const created = await post("/api/auth/admin/create-user", { username: "raceb", email: "b@race.test", name: "B", password, role: "admin" }, cookieA);
    expect(created.status).toBe(200);
    const b = ((await created.json()) as { user: { id: string } }).user.id;
    await db.prepare('UPDATE "user" SET username = ? WHERE id = ?').bind("raceb", b).run();
    const cookieB = await login("raceb");
    const original = db.prepare;
    let arrived = 0;
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => { release = resolve; });
    db.prepare = ((sql: string) => {
      const statement = original.call(db, sql);
      if (sql !== 'SELECT role FROM "user" WHERE COALESCE(banned, 0) = 0') return statement;
      const all = statement.all.bind(statement);
      statement.all = async (...args: Parameters<typeof all>) => {
        const result = await all(...args);
        if (++arrived === 2) release();
        await barrier;
        return result;
      };
      return statement;
    }) as typeof db.prepare;
    try {
      const results = await Promise.all([
        post("/api/auth/admin/ban-user", { userId: b }, cookieA),
        post("/api/auth/admin/ban-user", { userId: a }, cookieB),
      ]);
      expect(results.filter((response) => response.status === 200)).toHaveLength(1);
      // The losing caller can lose its own session before Better Auth checks it.
      expect([401, 409]).toContain(results.find((response) => response.status !== 200)?.status);
      const active = await db.prepare('SELECT id FROM "user" WHERE COALESCE(banned, 0) = 0').all();
      expect(active.results).toHaveLength(1);
    } finally { release(); db.prepare = original; }
  });
});
