import { Hono } from "hono";
import { getMigrations } from "better-auth/db/migration";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { constantTimeTokenMatches } from "../security/tokens";
import { ensureApplicationTables } from "../db/schema";

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
    await ensureApplicationTables(context.env);

    return context.json({ status: "migrated" });
  } catch {
    return context.json({ error: "Migration failed" }, 500);
  }
});
