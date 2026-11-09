/**
 * Duo secondary-authentication routes (Duo Free edition includes the Auth
 * API): the acting user verifies with Duo Push, SMS passcodes, phone callback
 * or a hardware-token passcode through the /auth/v2/auth call.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { createAuth } from "../auth/config";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import { duoAuthCall, duoConfig } from "./duo";

export const mfaRoutes = new Hono<{ Bindings: Env }>();

mfaRoutes.post("/mfa/duo/verify", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: "The Duo verification cannot be processed" }, 403);
  }
  if (!duoConfig(context.env)) return context.json({ error: "Duo secondary authentication is not configured" }, 503);
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "The Duo verification cannot be processed" }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "The Duo verification cannot be processed" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const factor = value.factor === "passcode" ? "passcode" : "auto";
  const passcode = typeof value.passcode === "string" ? value.passcode : null;
  if (factor === "passcode" && (!passcode || passcode.length > 64)) {
    return context.json({ error: "The Duo verification cannot be processed" }, 400);
  }
  return auditStandaloneOperation(context.env, "mfa.duo.verify", "/api/mfa/duo/verify", async () => {
    const result = await duoAuthCall(context.env, {
      user: session.user.email,
      factor,
      passcode,
    });
    if (!result) {
      return { response: Response.json({ error: "Duo secondary authentication is not configured" }, { status: 503 }), actorUserId: session.user.id };
    }
    return {
      response: Response.json({ result: result.result, status: result.status, statusMessage: result.statusMessage }),
      actorUserId: session.user.id,
    };
  });
});
