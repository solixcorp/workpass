import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { oidcOffboardingStatements } from "../src/db/oidc-offboarding";

function database() {
  const db = new Database(":memory:");
  db.exec(`CREATE TABLE "user" (id TEXT PRIMARY KEY, banned INTEGER);
    CREATE TABLE "oauthClient" (id TEXT PRIMARY KEY, backchannelLogoutUri TEXT);
    CREATE TABLE "oauthRefreshToken" (id TEXT PRIMARY KEY, userId TEXT, revoked INTEGER,
      rotationReplayResponse TEXT, rotationReplayExpiresAt INTEGER);
    CREATE TABLE "oauthAccessToken" (id TEXT PRIMARY KEY, userId TEXT, revoked INTEGER);`);
  return db;
}

function install(db: Database) {
  for (const sql of oidcOffboardingStatements) db.exec(sql);
}

describe("OIDC offboarding database guards", () => {
  test("ban revokes all user tokens and replay responses without touching other users", () => {
    const db = database();
    db.exec(`INSERT INTO "user" VALUES ('a', 0), ('b', 0);
      INSERT INTO "oauthRefreshToken" VALUES ('r1', 'a', NULL, 'cached', 42), ('r2', 'b', NULL, NULL, NULL);
      INSERT INTO "oauthAccessToken" VALUES ('a1', 'a', NULL), ('a2', 'b', NULL);`);
    install(db);
    db.exec(`UPDATE "user" SET banned = 1 WHERE id = 'a'`);
    const refresh = db.query('SELECT revoked, rotationReplayResponse, rotationReplayExpiresAt FROM "oauthRefreshToken" WHERE id = ?').get("r1") as Record<string, unknown>;
    expect(typeof refresh.revoked).toBe("number");
    expect(refresh.rotationReplayResponse).toBeNull();
    expect(refresh.rotationReplayExpiresAt).toBeNull();
    expect((db.query('SELECT revoked FROM "oauthAccessToken" WHERE id = ?').get("a1") as { revoked: number }).revoked).toBeGreaterThan(0);
    expect((db.query('SELECT revoked FROM "oauthRefreshToken" WHERE id = ?').get("r2") as { revoked: null }).revoked).toBeNull();
    db.exec(`UPDATE "user" SET banned = 0 WHERE id = 'a'`);
    expect((db.query('SELECT revoked FROM "oauthRefreshToken" WHERE id = ?').get("r1") as { revoked: number }).revoked).toBeGreaterThan(0);
    db.close();
  });

  test("blocked or missing users cannot receive new persisted tokens", () => {
    const db = database();
    db.exec(`INSERT INTO "user" VALUES ('a', 1), ('b', 0)`);
    install(db);
    for (const user of ["a", "missing"]) {
      expect(() => db.query('INSERT INTO "oauthRefreshToken" (id, userId) VALUES (?, ?)').run(`r-${user}`, user)).toThrow();
      expect(() => db.query('INSERT INTO "oauthAccessToken" (id, userId) VALUES (?, ?)').run(`a-${user}`, user)).toThrow();
    }
    db.exec(`INSERT INTO "oauthRefreshToken" (id, userId) VALUES ('ok', 'b');
      INSERT INTO "oauthAccessToken" (id, userId) VALUES ('machine', NULL);`);
    db.close();
  });

  test("installation revokes existing banned-user tokens and is repeatable", () => {
    const db = database();
    db.exec(`INSERT INTO "user" VALUES ('a', 1);
      INSERT INTO "oauthRefreshToken" VALUES ('r', 'a', NULL, 'cached', 42);
      INSERT INTO "oauthAccessToken" VALUES ('a', 'a', NULL);`);
    install(db);
    install(db);
    expect((db.query('SELECT revoked FROM "oauthRefreshToken"').get() as { revoked: number }).revoked).toBeGreaterThan(0);
    expect((db.query('SELECT revoked FROM "oauthAccessToken"').get() as { revoked: number }).revoked).toBeGreaterThan(0);
    db.close();
  });

  test("failed token revocation aborts the ban itself", () => {
    const db = database();
    db.exec(`INSERT INTO "user" VALUES ('a', 0);
      INSERT INTO "oauthRefreshToken" VALUES ('r', 'a', NULL, NULL, NULL);`);
    install(db);
    db.exec(`CREATE TRIGGER deny_revocation BEFORE UPDATE ON "oauthRefreshToken"
      BEGIN SELECT RAISE(ABORT, 'write failed'); END`);
    expect(() => db.exec(`UPDATE "user" SET banned = 1 WHERE id = 'a'`)).toThrow();
    expect((db.query('SELECT banned FROM "user" WHERE id = ?').get("a") as { banned: number }).banned).toBe(0);
    db.close();
  });

  test("backchannel targets require explicit exact approval", () => {
    const db = database();
    install(db);
    expect(() => db.exec(`INSERT INTO "oauthClient" VALUES ('a', 'https://rp.example/logout')`)).toThrow();
    db.exec(`INSERT INTO oidc_logout_uri_approvals VALUES ('https://rp.example/logout');
      INSERT INTO "oauthClient" VALUES ('a', 'https://rp.example/logout');`);
    expect(() => db.exec(`UPDATE "oauthClient" SET backchannelLogoutUri = 'https://rp.example/other' WHERE id = 'a'`)).toThrow();
    expect(() => db.exec(`DELETE FROM oidc_logout_uri_approvals WHERE uri = 'https://rp.example/logout'`)).toThrow();
    expect(() => db.exec(`UPDATE oidc_logout_uri_approvals SET uri = 'https://rp.example/other'`)).toThrow();
    db.close();
  });

  test("migration refuses to silently trust preexisting backchannel targets", () => {
    const db = database();
    db.exec(`INSERT INTO "oauthClient" VALUES ('a', 'https://rp.example/logout')`);
    expect(() => install(db)).toThrow();
    db.close();
  });
});
