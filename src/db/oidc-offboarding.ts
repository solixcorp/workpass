import type { Env } from "../env";

// These triggers run in the same SQLite write transaction as the account
// update or token insert. Do not revoke on ordinary session deletion: offline
// access is intentionally allowed to survive a normal sign-out.
export const oidcOffboardingStatements = [
  // An explicit operator-managed approval list prevents dynamic registration
  // and client updates from introducing arbitrary server-side fetch targets.
  `CREATE TABLE IF NOT EXISTS oidc_logout_uri_approvals (uri TEXT PRIMARY KEY NOT NULL)`,
  // Refuse to silently grandfather existing targets. Operators must inventory
  // and approve them explicitly before rerunning this migration.
  `CREATE TABLE IF NOT EXISTS oidc_logout_migration_guard (ok INTEGER NOT NULL CHECK (ok = 1))`,
  `INSERT INTO oidc_logout_migration_guard (ok)
   SELECT 0 WHERE EXISTS (SELECT 1 FROM "oauthClient" c WHERE c."backchannelLogoutUri" IS NOT NULL
     AND c."backchannelLogoutUri" <> '' AND NOT EXISTS
     (SELECT 1 FROM oidc_logout_uri_approvals a WHERE a.uri = c."backchannelLogoutUri"))`,
  `CREATE TRIGGER IF NOT EXISTS oidc_approved_logout_uri_insert
   BEFORE INSERT ON "oauthClient" WHEN NEW."backchannelLogoutUri" IS NOT NULL AND NEW."backchannelLogoutUri" <> ''
     AND NOT EXISTS (SELECT 1 FROM oidc_logout_uri_approvals WHERE uri = NEW."backchannelLogoutUri")
   BEGIN SELECT RAISE(ABORT, 'unapproved backchannel logout URI'); END`,
  `CREATE TRIGGER IF NOT EXISTS oidc_approved_logout_uri_update
   BEFORE UPDATE OF "backchannelLogoutUri" ON "oauthClient" WHEN NEW."backchannelLogoutUri" IS NOT NULL AND NEW."backchannelLogoutUri" <> ''
     AND NOT EXISTS (SELECT 1 FROM oidc_logout_uri_approvals WHERE uri = NEW."backchannelLogoutUri")
   BEGIN SELECT RAISE(ABORT, 'unapproved backchannel logout URI'); END`,
  `CREATE TRIGGER IF NOT EXISTS oidc_logout_approval_in_use
   BEFORE DELETE ON oidc_logout_uri_approvals WHEN EXISTS
     (SELECT 1 FROM "oauthClient" WHERE "backchannelLogoutUri" = OLD.uri)
   BEGIN SELECT RAISE(ABORT, 'logout URI approval is in use'); END`,
  `CREATE TRIGGER IF NOT EXISTS oidc_logout_approval_immutable
   BEFORE UPDATE ON oidc_logout_uri_approvals
   BEGIN SELECT RAISE(ABORT, 'replace approval instead of updating'); END`,
  `CREATE TRIGGER IF NOT EXISTS oidc_revoke_tokens_on_user_ban
   AFTER UPDATE OF banned ON "user"
   WHEN NEW.banned = 1
   BEGIN
     UPDATE "oauthRefreshToken" SET revoked = unixepoch() * 1000,
       rotationReplayResponse = NULL, rotationReplayExpiresAt = NULL
       WHERE "userId" = NEW.id;
     UPDATE "oauthAccessToken" SET revoked = unixepoch() * 1000
       WHERE "userId" = NEW.id;
   END`,
  `CREATE TRIGGER IF NOT EXISTS oidc_block_banned_refresh_insert
   BEFORE INSERT ON "oauthRefreshToken"
   WHEN NOT EXISTS (SELECT 1 FROM "user" WHERE id = NEW."userId" AND COALESCE(banned, 0) = 0)
   BEGIN SELECT RAISE(ABORT, 'inactive user cannot receive refresh tokens'); END`,
  `CREATE TRIGGER IF NOT EXISTS oidc_block_banned_access_insert
   BEFORE INSERT ON "oauthAccessToken"
   WHEN NEW."userId" IS NOT NULL AND NOT EXISTS
     (SELECT 1 FROM "user" WHERE id = NEW."userId" AND COALESCE(banned, 0) = 0)
   BEGIN SELECT RAISE(ABORT, 'inactive user cannot receive access tokens'); END`,
  // Clear pre-existing tokens too: installing a trigger is not retroactive.
  `UPDATE "oauthRefreshToken" SET revoked = unixepoch() * 1000,
     rotationReplayResponse = NULL, rotationReplayExpiresAt = NULL
   WHERE "userId" IN (SELECT id FROM "user" WHERE banned = 1)`,
  `UPDATE "oauthAccessToken" SET revoked = unixepoch() * 1000
   WHERE "userId" IN (SELECT id FROM "user" WHERE banned = 1)`,
] as const;

export async function installOidcOffboardingGuards(env: Env): Promise<void> {
  // D1 batch executes these statements atomically and in order.
  await env.DB.batch(oidcOffboardingStatements.map((sql) => env.DB.prepare(sql)));
}
