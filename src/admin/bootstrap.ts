import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { auditStandaloneOperation } from "../audit/store";
import { constantTimeTokenMatches } from "../security/tokens";

export const bootstrapRoutes = new Hono<{ Bindings: Env }>();

bootstrapRoutes.post("/bootstrap", async (context) => {
  const { ENABLE_ADMIN_BOOTSTRAP, ADMIN_BOOTSTRAP_TOKEN } = context.env;
  const authorization = context.req.header("authorization") ?? "";
  const providedToken = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  if (
    ENABLE_ADMIN_BOOTSTRAP !== "true" ||
    !ADMIN_BOOTSTRAP_TOKEN ||
    !constantTimeTokenMatches(providedToken, ADMIN_BOOTSTRAP_TOKEN)
  ) {
    return context.notFound();
  }

  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "Invalid JSON body" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return context.json({ error: "Invalid JSON body" }, 400);
  }
  const { email, name, username, password } = body as Record<string, unknown>;
  if (
    typeof email !== "string" || !email ||
    typeof name !== "string" || !name ||
    typeof username !== "string" || !username ||
    typeof password !== "string" || !password
  ) {
    return context.json(
      { error: "email, name, username, and password are required" },
      400,
    );
  }
  return auditStandaloneOperation(
    context.env,
    "identity.admin.bootstrap",
    "/api/admin/bootstrap",
    async () => {
      const { results } = await context.env.DB.prepare(
        'SELECT COUNT(*) AS count FROM "user"',
      ).all<{ count: number }>();
      const existingClaim = await context.env.DB.prepare(
        "SELECT slot FROM bootstrap_state WHERE slot = 1",
      ).first<{ slot: number }>();
      if ((results[0]?.count ?? 0) !== 0 || existingClaim) {
        return {
          response: Response.json(
            { error: "Bootstrap is only available before any user exists" },
            { status: 409 },
          ),
        };
      }

      const claim = await context.env.DB.prepare(
        "INSERT OR IGNORE INTO bootstrap_state (slot, claimed_at) VALUES (1, ?)",
      )
        .bind(new Date().toISOString())
        .run();
      if (claim.meta.changes !== 1) {
        return {
          response: Response.json(
            { error: "Bootstrap already claimed; inspect the user table before retrying" },
            { status: 409 },
          ),
        };
      }

      const auth = createAuth(context.env);
      let user: Awaited<ReturnType<typeof auth.api.createUser>>["user"];
      try {
        const result = await auth.api.createUser({
          body: {
            email,
            name,
            password,
            role: "admin",
            data: { username, emailVerified: true },
          },
        });
        user = result.user;
      } catch {
        try {
          // Creation can fail after a partial database write. Never reopen the
          // bootstrap gate unless the user table is still known to be empty.
          const remaining = await context.env.DB.prepare(
            'SELECT COUNT(*) AS count FROM "user"',
          ).first<{ count: number }>();
          if (remaining?.count === 0) {
            await context.env.DB.prepare("DELETE FROM bootstrap_state WHERE slot = 1").run();
          }
        } catch {
          // Keep the claim if it cannot be released; this fails closed.
        }
        throw new Error("Administrator bootstrap failed");
      }

      return {
        response: Response.json(
          { user: { id: user.id, email: user.email, name: user.name } },
          { status: 201 },
        ),
        actorUserId: user.id,
        targetUserId: user.id,
      };
    },
  );
});
