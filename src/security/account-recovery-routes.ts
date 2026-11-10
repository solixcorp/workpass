/**
 * Admin-issued account recovery tokens and one-time redemption, the recovery
 * path for locked accounts (docs/security/account-lockdown.md). There is no
 * email infrastructure here, so the administrator delivers the token out of
 * band; redemption is unauthenticated, single-use, short-lived, and
 * rate-limited per IP.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "./authorization";
import { auditStandaloneOperation } from "../audit/store";
import {
  issueRecoveryToken,
  redeemRecoveryToken,
  cleanupRecoveryTokens,
} from "./account-recovery";

export const recoveryRoutes = new Hono<{ Bindings: Env }>();

const ISSUE_PATH = "/api/security/account-recovery";
const REDEEM_PATH = "/api/security/account-recovery/redeem";

// Administrator issues a recovery token for a currently locked account.
recoveryRoutes.post("/account-recovery", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;

  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "Invalid request" }, 400);
  }
  const value = (body ?? {}) as Record<string, unknown>;
  const userId = typeof value.userId === "string" ? value.userId : "";
  if (!userId || userId.length > 128) return context.json({ error: "userId is required" }, 400);
  const ttl = typeof value.ttlMinutes === "number" && Number.isInteger(value.ttlMinutes)
    ? value.ttlMinutes
    : undefined;

  return auditStandaloneOperation(context.env, "identity.user.recovery_link.issued", ISSUE_PATH, async () => {
    const result = await issueRecoveryToken({
      env: context.env,
      userId,
      actorUserId: admin.userId,
      ttlMinutes: ttl,
    });
    if (result.status !== "issued") {
      const status = result.status === "user_not_found" ? 404
        : result.status === "no_active_lockdown" ? 409
        : 503;
      const error = result.status === "user_not_found" ? "Account not found"
        : result.status === "no_active_lockdown" ? "Account is not under an active lockdown"
        : "The recovery link could not be recorded";
      return {
        response: context.json({ error }, { status }),
        actorUserId: admin.userId,
        targetUserId: userId,
      };
    }
    return {
      response: context.json(
        {
          recoveryToken: result.recovery.token,
          expiresAt: result.recovery.expiresAt,
          redemption: {
            method: "POST",
            path: REDEEM_PATH,
            body: { token: "<recoveryToken>", new_password: "<new password>" },
          },
        },
        { status: 201 },
      ),
      actorUserId: admin.userId,
      targetUserId: userId,
    };
  });
});

// One-time redemption. Unauthenticated by design: the token is the proof of
// identity for the reset, delivered out of band by an administrator.
recoveryRoutes.post("/account-recovery/redeem", async (context) => {
  if (!(await recoveryRedemptionBudget(context.env, context))) {
    return context.json({ error: "Too many recovery attempts" }, { status: 429 });
  }

  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "Invalid request" }, 400);
  }
  const value = (body ?? {}) as Record<string, unknown>;
  const token = typeof value.token === "string" ? value.token : "";
  const newPassword = typeof value.new_password === "string" ? value.new_password : "";
  if (!token || newPassword.length < 8 || newPassword.length > 128) {
    return context.json({ error: "token and new_password (8-128 characters) are required" }, 400);
  }

  return auditStandaloneOperation(context.env, "identity.user.account_recovery", REDEEM_PATH, async () => {
    const result = await redeemRecoveryToken({ env: context.env, token, newPassword });
    if (result.status !== "recovered") {
      const status = result.status === "no_active_lockdown" ? 409 : 400;
      const error = result.status === "invalid_or_expired" ? "The recovery link is invalid or expired"
        : result.status === "already_used" ? "The recovery link was already used"
        : "The account is not under an active lockdown";
      return {
        response: context.json({ error }, { status }),
        actorUserId: null,
      };
    }
    return {
      response: context.json({
        status: "recovered",
        nextSteps: "Sign in with the new password. Trusted devices and sessions were revoked; verify MFA enrollments.",
      }),
      actorUserId: result.userId,
      targetUserId: result.userId,
    };
  });
});

/** Per-IP redemption budget; brute force is infeasible, this only caps noise. */
async function recoveryRedemptionBudget(env: Env, context: { req: { raw: Request } }): Promise<boolean> {
  const ip = context.req.raw.headers.get("cf-connecting-ip") ?? "local";
  const nowMinute = Math.floor(Date.now() / 60_000);
  const result = await env.DB.prepare(
    `INSERT INTO fingerprint_lookup_limits (budget_key, window_start, request_count)
     VALUES (?, ?, 1)
     ON CONFLICT(budget_key) DO UPDATE SET
       request_count = CASE
         WHEN fingerprint_lookup_limits.window_start = excluded.window_start
         THEN fingerprint_lookup_limits.request_count + 1
         ELSE 1
       END,
       window_start = excluded.window_start
     RETURNING request_count`,
  )
    .bind(`account_recovery:${ip}`, nowMinute)
    .first<{ request_count: number }>()
    .catch(() => null);
  // Fail open on budget-store errors; the single-use 256-bit token carries the
  // protection, not this counter.
  return result === null ? true : (result.request_count ?? Number.POSITIVE_INFINITY) <= 10;
}
