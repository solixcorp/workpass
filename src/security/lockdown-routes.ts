/**
 * Account Lockdown routes: administrator emergency lockdown and lift, plus
 * the self-service "lock my account" path (docs/security/account-lockdown.md).
 * Modeled on authentik's Account Lockdown feature.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator, requireSameOrigin } from "./authorization";
import { auditStandaloneOperation } from "../audit/store";
import { createAuth } from "../auth/config";
import { hashPassword } from "../auth/password";
import {
  latestAccountLockdowns,
  liftAccountLockdown,
  performAccountLockdown,
  type LockdownSource,
} from "./account-lockdown";

export const lockdownRoutes = new Hono<{ Bindings: Env }>();

const REQUEST_PATH = "/api/security/account-lockdown";

function lockdownRequestPath(userId: string): string {
  return `${REQUEST_PATH}/user/${encodeURIComponent(userId)}`;
}

function parseReason(context: { body: Record<string, unknown> }): string | null {
  const reason = typeof context.body.reason === "string" ? context.body.reason.trim() : "";
  if (reason.length < 1 || reason.length > 500) return null;
  return reason;
}

async function readBody(context: {
  req: { json: () => Promise<unknown> };
}): Promise<Record<string, unknown> | null> {
  try {
    const body = await context.req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

// Self-service lockdown: a signed-in user locks their own account. The acting
// session is destroyed by the lockdown itself, so the response is final.
lockdownRoutes.post("/account-lockdown", async (context) => {
  const originFailure = requireSameOrigin(context);
  if (originFailure) return originFailure;
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  const body = await readBody(context);
  if (!body) return context.json({ error: "Invalid request" }, 400);
  const reason = parseReason({ body });
  if (!reason) return context.json({ error: "reason is required (1-500 characters)" }, 400);

  return auditStandaloneOperation(
    context.env,
    "identity.user.lockdown",
    REQUEST_PATH,
    async () => {
      const result = await performAccountLockdown({
        env: context.env,
        userId: session.user.id,
        actorUserId: session.user.id,
        source: "self_service" as LockdownSource,
        reason,
      });
      if (result.status === "performed") {
        return {
          response: context.json({ status: "locked", lockdownId: result.lockdownId }, 200),
          actorUserId: session.user.id,
          targetUserId: session.user.id,
        };
      }
      if (result.status === "already_locked") {
        return {
          response: context.json({ error: "Account is already locked" }, { status: 409 }),
          actorUserId: session.user.id,
          targetUserId: session.user.id,
        };
      }
      return {
        response: context.json({ error: "Account not found" }, { status: 404 }),
        actorUserId: session.user.id,
      };
    },
  );
});

// Administrator emergency lockdown for an arbitrary account.
lockdownRoutes.post("/account-lockdown/user/:userId", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;

  const userId = context.req.param("userId");
  const body = await readBody(context);
  if (!body) return context.json({ error: "Invalid request" }, 400);
  const reason = parseReason({ body });
  if (!reason) return context.json({ error: "reason is required (1-500 characters)" }, 400);

  return auditStandaloneOperation(
    context.env,
    "identity.user.lockdown",
    lockdownRequestPath(userId),
    async () => {
      const result = await performAccountLockdown({
        env: context.env,
        userId,
        actorUserId: admin.userId,
        source: "admin" as LockdownSource,
        reason,
      });
      if (result.status === "performed") {
        return {
          response: context.json(
            {
              status: "locked",
              lockdownId: result.lockdownId,
              actions: {
                revokedSessions: result.revokedSessions,
                passwordDisabled: true,
                opaqueCredentialsRemoved: result.removedOpaqueCredentials,
                trustedDevicesRevoked: result.revokedTrustedDevices,
              },
            },
            200,
          ),
          actorUserId: admin.userId,
          targetUserId: userId,
        };
      }
      if (result.status === "already_locked") {
        return {
          response: context.json({ error: "Account is already locked" }, { status: 409 }),
          actorUserId: admin.userId,
          targetUserId: userId,
        };
      }
      return {
        response: context.json({ error: "Account not found" }, { status: 404 }),
        actorUserId: admin.userId,
      };
    },
  );
});

// Administrator unlock. The unusable password stays until the administrator
// sets a new one here or through `/api/auth/admin/set-user-password`; users
// then re-enroll trusted devices on their next sign-in.
lockdownRoutes.post("/account-lockdown/user/:userId/unlock", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;

  const userId = context.req.param("userId");
  const body = await readBody(context);
  if (!body) return context.json({ error: "Invalid request" }, 400);

  let newHashedPassword: string | null = null;
  if (typeof body.new_password === "string") {
    const password = body.new_password;
    if (password.length < 8 || password.length > 128) {
      return context.json({ error: "new_password must be 8-128 characters" }, 400);
    }
    newHashedPassword = await hashPassword(password);
  }

  return auditStandaloneOperation(
    context.env,
    "identity.user.lockdown_lifted",
    `${lockdownRequestPath(userId)}/unlock`,
    async () => {
      const result = await liftAccountLockdown({
        env: context.env,
        userId,
        actorUserId: admin.userId,
        newHashedPassword,
      });
      if (result.status === "lifted") {
        return {
          response: context.json(
            {
              status: "unlocked",
              liftedAt: result.liftedAt,
              passwordReset: result.passwordReset,
              nextSteps:
                "Set a new password if one has not been provided; trusted devices and sessions remain revoked. Advise the user to re-verify their MFA enrollments.",
            },
            200,
          ),
          actorUserId: admin.userId,
          targetUserId: userId,
        };
      }
      if (result.status === "user_not_found") {
        return {
          response: context.json({ error: "Account not found" }, { status: 404 }),
          actorUserId: admin.userId,
        };
      }
      return {
        response: context.json({ error: "No active account lockdown" }, { status: 409 }),
        actorUserId: admin.userId,
        targetUserId: userId,
      };
    },
  );
});

// History for an administrator; includes lockdown reasons (restricted audience).
lockdownRoutes.get("/account-lockdown/user/:userId", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const histories = await latestAccountLockdowns(context.env, context.req.param("userId"));
  return context.json({ lockdowns: histories });
});

lockdownRoutes.get("/account-lockdown/self", async (context) => {
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const histories = await latestAccountLockdowns(context.env, session.user.id);
  return context.json({ lockdowns: histories });
});
