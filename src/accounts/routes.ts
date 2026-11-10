/**
 * User-facing multi-account switching. The acting session lists its
 * memberships and binds an active account to itself; every mutation is
 * same-origin, audited, and membership-verified inside the store call.
 */

import { Hono } from "hono";
import { createAuth } from "../auth/config";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import {
  listUserAccountMemberships,
  redeemAccountInvitation,
  switchActiveAccount,
} from "./store";

export const accountRoutes = new Hono<{ Bindings: Env }>();

const GENERIC_REJECTION = "The request cannot be processed";
const SESSION_TOKEN_LIMIT = 512;

/** The Better Auth session of the caller, or null when unauthenticated. */
async function actingSession(context: { env: Env; req: { raw: Request } }) {
  return await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
}

function sessionToken(session: unknown): string | null {
  const token = (session as { session?: { token?: unknown } })?.session?.token;
  return typeof token === "string" && token.length > 0 && token.length <= SESSION_TOKEN_LIMIT ? token : null;
}

accountRoutes.use("/api/accounts", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});
accountRoutes.use("/api/accounts/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

accountRoutes.get("/api/accounts", async (context) => {
  const session = await actingSession(context);
  if (!session) return context.json({ error: GENERIC_REJECTION }, 401);
  const { memberships, activeAccountId } = await listUserAccountMemberships(
    context.env,
    session.user.id,
    sessionToken(session),
  );
  return context.json({ accounts: memberships, activeAccountId });
});

/** The Better Auth session id (`sid` of protocol tokens) bound to a context. */
function sessionId(session: unknown): string | null {
  const id = (session as { session?: { id?: unknown } })?.session?.id;
  return typeof id === "string" && id.length > 0 && id.length <= SESSION_TOKEN_LIMIT ? id : null;
}

accountRoutes.post("/api/accounts/switch", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: GENERIC_REJECTION }, 403);
  }
  const session = await actingSession(context);
  if (!session) return context.json({ error: GENERIC_REJECTION }, 401);
  const token = sessionToken(session);
  if (!token) return context.json({ error: GENERIC_REJECTION }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: GENERIC_REJECTION }, 400); }
  if (!body || typeof body !== "object") return context.json({ error: GENERIC_REJECTION }, 400);
  const { accountId } = body as Record<string, unknown>;
  if (typeof accountId !== "string" || accountId.length === 0 || accountId.length > 128) {
    return context.json({ error: GENERIC_REJECTION }, 400);
  }
  return auditStandaloneOperation(context.env, "account.switched", "/api/accounts/switch", async () => {
    const account = await switchActiveAccount(
      context.env,
      token,
      sessionId(session),
      session.user.id,
      accountId,
    );
    if (!account) {
      // A nonexistent account and a non-membership are indistinguishable to
      // the caller: no account existence oracle leaks over the user surface.
      return { response: Response.json({ error: GENERIC_REJECTION }, { status: 403 }), actorUserId: session.user.id };
    }
    return {
      response: Response.json({ activeAccount: account }),
      actorUserId: session.user.id,
      targetUserId: account.id,
    };
  });
});

accountRoutes.post("/api/accounts/join", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: GENERIC_REJECTION }, 403);
  }
  const session = await actingSession(context);
  if (!session) return context.json({ error: GENERIC_REJECTION }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: GENERIC_REJECTION }, 400); }
  if (!body || typeof body !== "object") return context.json({ error: GENERIC_REJECTION }, 400);
  const { token } = body as Record<string, unknown>;
  if (typeof token !== "string" || token.length === 0 || token.length > 256) {
    return context.json({ error: GENERIC_REJECTION }, 400);
  }
  return auditStandaloneOperation(context.env, "account.joined", "/api/accounts/join", async () => {
    const redeemed = await redeemAccountInvitation(context.env, token, session.user.id);
    if ("reason" in redeemed) {
      // Invalid, expired, burned and already-member invitations all resolve
      // to one identical rejection: the token existence or state must not be
      // distinguishable to non-members.
      return { response: Response.json({ error: GENERIC_REJECTION }, { status: 403 }), actorUserId: session.user.id };
    }
    return {
      response: Response.json({ account: redeemed.account, role: redeemed.role }, { status: 201 }),
      actorUserId: session.user.id,
      targetUserId: redeemed.account.id,
    };
  });
});
