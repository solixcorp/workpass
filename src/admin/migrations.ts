import { Hono } from "hono";
import { getMigrations } from "better-auth/db/migration";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { constantTimeTokenMatches } from "../security/tokens";
import { ensureApplicationTables } from "../db/schema";
import { installOidcOffboardingGuards } from "../db/oidc-offboarding";
import { insertAuditEvent } from "../audit/store";

export const migrationRoutes = new Hono<{ Bindings: Env }>();

migrationRoutes.post("/migrate", async (context) => {
  const { ENABLE_MIGRATIONS, MIGRATION_TOKEN } = context.env;
  if (ENABLE_MIGRATIONS !== "true" || !MIGRATION_TOKEN) {
    return context.notFound();
  }

  const authorization = context.req.header("authorization") ?? "";
  const providedToken = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  if (!constantTimeTokenMatches(providedToken, MIGRATION_TOKEN)) {
    return context.json({ error: "Unauthorized" }, 401);
  }

  // The migration mutates the schema and creates the audit table itself, so a
  // first-run migration cannot have a preceding audit row; the completed event
  // is written after the application tables exist. Every later migration run
  // is audited the same way, without a session actor (token-protected route).
  try {
    const auth = createAuth(context.env);
    const migrations = await getMigrations(auth.options, { throwOnUnsafe: false });
    if (migrations.unsafeChanges.length > 0) {
      return context.json(
        { error: "Unsafe schema changes require a reviewed migration plan" },
        409,
      );
    }

    await migrations.runMigrations();
    await installOidcOffboardingGuards(context.env);
    await ensureApplicationTables(context.env);

    try {
      await insertAuditEvent(context.env, {
        id: crypto.randomUUID(),
        actor_user_id: null,
        target_user_id: null,
        event_type: "admin.migration.executed",
        outcome: "success",
        request_path: "/_internal/migrate",
      });
    } catch {
      // The schema mutation already applied; surface the audit gap loudly for
      // operator reconciliation instead of falsely reporting a failed migration.
      console.error("Migration succeeded but the audit event could not be recorded");
    }

    return context.json({ status: "migrated" });
  } catch (error) {
    // Server-side only: the operator needs the failure reason in the logs.
    console.error("Migration failed", {
      name: error instanceof Error ? error.name : "UnknownError",
      message: error instanceof Error ? error.message : "no message",
    });
    return context.json({ error: "Migration failed" }, 500);
  }
});
