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
import { sealString } from "../crypto/sealed";
import { generateHotpSecret, hotpVerify, userHasHotpToken } from "./hotp";


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
  // This deployment uses Duo for PUSH NOTIFICATIONS ONLY. SMS passcodes and
  // hardware-token passcodes are managed by the platform's own factors
  // (phone-number OTP and HOTP tokens), not through Duo.
  return auditStandaloneOperation(context.env, "mfa.duo.verify", "/api/mfa/duo/verify", async () => {
    const result = await duoAuthCall(context.env, {
      user: session.user.email,
      factor: "push",
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

// --- Hardware OTP (HOTP) tokens managed by this platform ---------------------

mfaRoutes.post("/mfa/hotp/enroll", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: "The hardware token enrollment cannot be processed" }, 403);
  }
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "The hardware token enrollment cannot be processed" }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "The hardware token enrollment cannot be processed" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const label = typeof value.label === "string" && value.label.length > 0 && value.label.length <= 64 ? value.label : "";
  if (label.length === 0) return context.json({ error: "The hardware token enrollment cannot be processed" }, 400);
  const secret = await generateHotpSecret();
  const sealedSecret = await sealString(context.env, secret, `mfa_hotp_token:${session.user.id}`);
  const id = crypto.randomUUID();
  await context.env.DB.prepare(
    "INSERT INTO mfa_hotp_tokens (id, user_id, label, secret_base32, counter, created_at) VALUES (?, ?, ?, ?, 0, ?)",
  ).bind(id, session.user.id, label, sealedSecret, new Date().toISOString()).run();
  return auditStandaloneOperation(context.env, "mfa.hotp.enroll", "/api/mfa/hotp/enroll", async () => ({
    response: Response.json({ tokenId: id, label, secretBase32: secret }, { status: 201 }),
    actorUserId: session.user.id,
  }));
});

mfaRoutes.post("/mfa/hotp/verify", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: "The verification cannot be processed" }, 403);
  }
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "The verification cannot be processed" }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "The verification cannot be processed" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const code = typeof value.code === "string" ? value.code : "";
  return auditStandaloneOperation(context.env, "mfa.hotp.verify", "/api/mfa/hotp/verify", async () => {
    const result = await hotpVerify(context.env, session.user.id, code);
    return {
      response: Response.json({ verified: result.verified }, { status: result.verified ? 200 : 400 }),
      actorUserId: session.user.id,
    };
  });
});

// The admin-facing second-factor check used by the SSO routes; SAML and
// WS-Fed call the shared userSatisfiesRequireMfa helper directly
// (src/mfa/second-factor.ts).
mfaRoutes.get("/mfa/second-factor", async (context) => {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const twoFactorEnabled = session.user.twoFactorEnabled === true;
  const hotp = await userHasHotpToken(context.env, session.user.id);
  return context.json({ secondFactor: twoFactorEnabled || hotp, via: twoFactorEnabled ? "better-auth" : hotp ? "hardware-otp" : null });
});

